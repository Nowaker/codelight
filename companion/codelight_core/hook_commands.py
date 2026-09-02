from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import sys
import threading
import time
import uuid
from collections.abc import Callable

from codelight_core import hook_io
from codelight_core import hook_runtime
from codelight_core import policy as policy_core
from codelight_core import transcript as transcript_core
from codelight_core.agents import base as agents_base
from codelight_core.evidence_order import authority_rank_for_state, evidence_order
from codelight_core.lifecycle import (
    ProcessIdentity,
    authority_scope_key,
    process_generation_key,
)
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore


AgentNameCallback = Callable[[str | None], str]
AgentDisplayCallback = Callable[[str | None], str]
ProcessIdentityCallback = Callable[[str], ProcessIdentity | None]
_EVENT_LEASE_NS = 600 * 1_000_000_000
_NO_EXPIRY_NS = 9_223_372_036_854_775_807


def lease_deadline_ns(state: str, order_token: int) -> int:
    if state in ("idle", "ended"):
        return _NO_EXPIRY_NS
    return order_token + _EVENT_LEASE_NS


def legacy_status_state(data: dict) -> str:
    event_name = hook_runtime.hook_event_name(data)
    match event_name:
        case "Stop" | "SessionEnd":
            return "ended"
        case "SessionStart":
            return "idle"
        case "PermissionRequest" | "Notification":
            return "waiting"
        case (
            "UserPromptSubmit"
            | "PreToolUse"
            | "PostToolUse"
            | "PostToolUseFailure"
            | "SubagentStart"
            | "SubagentStop"
        ):
            return "working"
        case _:
            return "unknown"


def resolve_hook_agent(agent_id: str) -> tuple[str, str]:
    """Resolve the agent that actually ran this hook, and its session id.

    Grok runs other harnesses' hooks via its compatibility layer (Claude
    Code / Cursor), which would otherwise be misattributed to `--agent
    claude`/`cursor`. Grok sets GROK_* env on every hook it runs, so detect it
    and re-tag to grok (with its own GROK_SESSION_ID). Returns (agent_id,
    session_id_override) where the override is "" when the payload's own
    session id should be used.
    """
    grok_session = os.environ.get("GROK_SESSION_ID", "")
    if grok_session or os.environ.get("GROK_HOOK_EVENT"):
        return "grok", grok_session
    return agent_id, ""


def run_status_hook(
    state: str,
    *,
    agent_id: str,
    socket_path: str,
    monitor_state_dir: str,
    normalize_agent_id: AgentNameCallback,
    input_text: str | None = None,
    evidence_store: LifecycleEvidenceStore | None = None,
    process_identity: ProcessIdentityCallback = lambda _agent_id: None,
) -> None:
    """Send a fast status event to the daemon, falling back to monitor_state."""
    data = hook_runtime.parse_json_object(
        sys.stdin.read() if input_text is None else input_text)
    agent_id, session_override = resolve_hook_agent(agent_id)
    session_id = session_override or hook_runtime.session_id(data)
    transcript_path = transcript_core.extract_transcript_path(data)
    hook_event = hook_runtime.hook_event_name(data)
    normalized_agent = normalize_agent_id(agent_id)
    observed_at = time.time()
    provider_evidence_complete = data.get("provider_evidence_complete") is not False
    operation = evidence_order(
        time.monotonic_ns(),
        authority_rank_for_state(state, provider_evidence_complete),
    )
    lease_deadline = lease_deadline_ns(state, operation.token)
    cwd_value = data.get("cwd")
    if not isinstance(cwd_value, str):
        workspace_roots = data.get("workspace_roots")
        cwd_value = (
            workspace_roots[0]
            if isinstance(workspace_roots, list)
            and workspace_roots
            and isinstance(workspace_roots[0], str)
            else ""
        )
    scope_id = (
        os.path.realpath(cwd_value)
        if cwd_value and not provider_evidence_complete
        else ""
    )

    identity = process_identity(normalized_agent)
    evidence_persisted = evidence_store is None
    if evidence_store is not None:
        try:
            if identity is None:
                evidence_store.invalidate_agent(
                    normalized_agent,
                    operation.token,
                    operation.operation_id,
                )
            else:
                evidence_store.record(
                    agent_id=normalized_agent,
                    identity=identity,
                    session_id=session_id,
                    state=state,
                    observed_at=observed_at,
                    hook_event=hook_event,
                    complete=provider_evidence_complete,
                    scope_id=scope_id,
                    order_token=operation.token,
                    authority_rank=operation.authority_rank,
                    operation_id=operation.operation_id,
                    lease_deadline_ns=lease_deadline,
                )
            evidence_persisted = True
        except (OSError, sqlite3.Error):
            evidence_persisted = False
    authority_scope = (
        authority_scope_key(normalized_agent, identity, scope_id)
        if identity is not None
        else f"unresolved:{normalized_agent}"
    )
    authority_generation = (
        process_generation_key(normalized_agent, identity)
        if identity is not None
        else ""
    )

    if hook_io.send_json(
        socket_path,
        {
            "state": state,
            "session_id": session_id,
            "agent_id": normalized_agent,
            "transcript_path": transcript_path,
            "cwd": cwd_value,
            "hook_event": hook_event,
            "observed_at": observed_at,
            "order_token": operation.token,
            "authority_rank": operation.authority_rank,
            "operation_id": operation.operation_id,
            "lease_deadline_ns": lease_deadline,
            "authority_scope": authority_scope,
            "authority_generation": authority_generation,
            "provider_evidence_complete": (
                provider_evidence_complete
                and evidence_persisted
                and identity is not None
            ),
        },
        timeout=0.5,
    ):
        return

    hook_io.write_monitor_state(
        monitor_state_dir,
        session_id=session_id,
        state=state,
        agent_id=normalized_agent,
        hook_event=hook_event,
    )


def emit_permission_decision(
    decision: str,
    *,
    envelope: str,
    reason: str = "",
) -> None:
    """Emit the host-specific decision envelope from one shared policy path."""
    print(json.dumps(hook_runtime.permission_decision_output(
        decision,
        envelope=envelope,
        reason=reason,
    )))


def run_permission_hook(
    *,
    mode: agents_base.HookMode,
    agent_id: str | None = None,
    socket_path: str,
    monitor_state_dir: str,
    policy_path: str,
    policy_lock: threading.Lock,
    hook_wait_ceiling: int,
    normalize_agent_id: AgentNameCallback,
    agent_display_name: AgentDisplayCallback,
    auto_allow_tools: Callable[[str], frozenset[str]] = lambda agent_id: frozenset(),
    input_text: str | None = None,
) -> None:
    """Forward a permission prompt to the daemon or fall back to local prompt."""
    data = hook_runtime.parse_json_object(
        sys.stdin.read() if input_text is None else input_text)
    resolved_agent, session_override = resolve_hook_agent(
        agent_id or mode.default_agent_id)
    session_id = session_override or hook_runtime.session_id(data)
    normalized_agent = normalize_agent_id(resolved_agent)
    tool_name = hook_runtime.tool_name(data)
    tool_input = hook_runtime.tool_input(data)
    cwd = str(data.get("cwd") or "")

    # Cursor payload shapes: beforeShellExecution carries the command at the
    # top level (no tool_name), and beforeMCPExecution serializes tool_input
    # as a JSON string.
    if tool_name == "?" and isinstance(data.get("command"), str):
        tool_name = "Bash"
        tool_input = {"command": data["command"]}
    if not tool_input and isinstance(data.get("tool_input"), str):
        parsed = hook_runtime.parse_json_object(data["tool_input"])
        if parsed:
            tool_input = parsed

    if mode.requires_tool_use_id and not data.get("tool_use_id"):
        return

    if hook_runtime.is_question_tool(tool_name, tool_input):
        return

    if policy_core.is_safe_memory_read(tool_name, tool_input):
        emit_permission_decision(
            "allow",
            envelope=mode.envelope,
            reason="Read-only memory view in repo/session scope")
        return

    if policy_core.is_allowed_command(policy_path, tool_name, tool_input, cwd):
        emit_permission_decision(
            "allow",
            envelope=mode.envelope,
            reason="Exact command allowed by codelight policy")
        return

    if policy_core.is_allowed_tool(policy_path, tool_name):
        policy_core.touch_allowed_tool(policy_path, policy_lock, tool_name)
        emit_permission_decision(
            "allow",
            envelope=mode.envelope,
            reason="Tool always allowed by codelight policy")
        return

    if policy_core.is_safe_trusted_apply_patch(
        policy_path, tool_name, tool_input, cwd):
        emit_permission_decision(
            "allow",
            envelope=mode.envelope,
            reason="apply_patch target is within trusted codelight folder")
        return

    if (
        policy_core.is_trusted_repo_cwd(policy_path, cwd)
        and tool_name in auto_allow_tools(normalized_agent)
    ):
        emit_permission_decision(
            "allow",
            envelope=mode.envelope,
            reason="Read-only tool in trusted codelight folder")
        return

    truncated = (
        policy_core.truncate_tool_input(
            tool_input, max_str=8000, max_total=12000)
        if tool_name == "ExitPlanMode"
        else policy_core.truncate_tool_input(tool_input)
    )
    request = {
        "type":       "permission_request",
        "session_id": session_id,
        "agent_id":   normalized_agent,
        "agent_display": agent_display_name(normalized_agent),
        "prompt_id":  data.get("prompt_id") or uuid.uuid4().hex,
        "tool_name":  tool_name,
        "summary":    policy_core.tool_summary(tool_name, tool_input),
        "tool_input": truncated,
        "policy_command": policy_core.command_from_tool(tool_name, tool_input),
        "cwd":        cwd,
    }

    decision = None
    try:
        response = hook_io.request_json(
            socket_path,
            request,
            connect_timeout=2.0,
            response_timeout=hook_wait_ceiling,
            max_bytes=4096,
        )
        decision = response.get("decision") if response else None
    except Exception:
        try:
            hook_io.write_monitor_state(
                monitor_state_dir,
                session_id=session_id,
                state="waiting",
                agent_id=normalized_agent,
            )
        except Exception:
            pass

    if decision in ("allow", "deny"):
        emit_permission_decision(
            decision,
            envelope=mode.envelope,
            reason="Denied by remote codelight approval" if decision == "deny" else "")
    elif mode.fallback_decision:
        # No remote decision — hand back to the agent's own prompt explicitly
        # (e.g. Cursor's {"permission": "ask"}).
        emit_permission_decision(mode.fallback_decision, envelope=mode.envelope)


def run_question_hook(
    *,
    mode: agents_base.HookMode,
    agent_id: str | None = None,
    socket_path: str,
    hook_wait_ceiling: int,
    normalize_agent_id: AgentNameCallback,
    agent_display_name: AgentDisplayCallback,
    input_text: str | None = None,
) -> None:
    """Forward AskUserQuestion prompts to the daemon and emit hook output."""
    resolved_agent, session_override = resolve_hook_agent(
        agent_id or mode.default_agent_id)
    normalized_agent = normalize_agent_id(resolved_agent)

    data = hook_runtime.parse_json_object(
        sys.stdin.read() if input_text is None else input_text)
    tool_input = hook_runtime.tool_input(data)
    questions = hook_runtime.questions_from_input(data, tool_input)
    if not questions:
        return

    request = {
        "type":       "question_request",
        "session_id": session_override or hook_runtime.session_id(data),
        "agent_id":   normalized_agent,
        "agent_display": agent_display_name(normalized_agent),
        "prompt_id":  data.get("prompt_id") or uuid.uuid4().hex,
        "questions":  questions,
        "cwd":        data.get("cwd", ""),
    }

    try:
        response = hook_io.request_json(
            socket_path,
            request,
            connect_timeout=2.0,
            response_timeout=hook_wait_ceiling,
            max_bytes=65536,
        )
        answers = response.get("answers") if response else None
        if isinstance(answers, dict) and answers:
            if mode.envelope == agents_base.CONTEXT:
                print(json.dumps(hook_runtime.question_context_output(answers)))
            else:
                print(json.dumps(
                    hook_runtime.question_updated_input_output(tool_input, answers)
                ))
    except Exception:
        pass
