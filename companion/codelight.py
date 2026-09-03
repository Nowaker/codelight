#!/usr/bin/env python3
"""
codelight.py - pushes coding-agent status to codelight clients.

Usage:
    python3 codelight.py --name my-laptop
    python3 codelight.py dashboard
    python3 codelight.py --name my-laptop --verbose   # also show socket events and API data
    python3 -u codelight.py | tee                         # -u avoids buffering when piping
"""
import argparse
import asyncio
import collections
import ipaddress
import json
import os
import signal
import sqlite3
import sys
import threading
import time
from datetime import datetime
from codelight_core.agents.registry import AgentRegistry
from codelight_core.agents import base as agents_base
from codelight_core import conversation as conversation_core
from codelight_core.conversation import ConversationRefresher
from codelight_core import dashboard_client
from codelight_core import discovery as discovery_core
from codelight_core.evidence_order import (
    UNKNOWN_RANK,
    evidence_order,
    inventory_scan_failure_order,
)
from codelight_core import hook_commands
from codelight_core import hook_runtime
from codelight_core import invocation
from codelight_core import lifecycle
from codelight_core import lifecycle_evidence
from codelight_core import lifecycle_snapshot
from codelight_core import policy as policy_core
from codelight_core import power_status_file
from codelight_core import remote_control
from codelight_core.power_authority import AuthoritySession, parse_session_state
from codelight_core import remote_payloads
from codelight_core import socket_server
from codelight_core.state import CodelightState
from codelight_core import transcript as transcript_core
from codelight_core.usage import UsagePoller
from codelight_core.ws_server import CodelightWebsocketHub, DEFAULT_LISTEN_HOST

try:
    import websockets as _websockets
    _have_websockets = True
except ImportError:
    _have_websockets = False

# ── Config ────────────────────────────────────────────────────────────────────

CODELIGHT_CONFIG_HOME = os.path.expanduser(
    os.environ.get("CODELIGHT_CONFIG_HOME", "~/.config/codelight"))
MONITOR_STATE_DIR = os.path.join(CODELIGHT_CONFIG_HOME, "monitor_state")
SOCKET_PATH       = os.path.join(CODELIGHT_CONFIG_HOME, "codelight.sock")
POLICY_PATH       = os.path.join(CODELIGHT_CONFIG_HOME, "policy.json")
# Daemon-owned, runtime-mutable settings (e.g. app-set agent budgets). Kept
# separate from the user's hand-authored config.json so the daemon never
# rewrites it.
SETTINGS_PATH     = os.path.join(CODELIGHT_CONFIG_HOME, "settings.json")
POWER_STATUS_PATH = os.path.join(CODELIGHT_CONFIG_HOME, "power-status.json")
LIFECYCLE_EVIDENCE_PATH = os.path.join(MONITOR_STATE_DIR, "evidence.sqlite3")
USAGE_INTERVAL      = 60   # seconds between usage API polls
POWER_STATUS_INTERVAL = 15
IDLE_WINDOW         = 600  # seconds before a silent "working" session is dropped
IDLE_WINDOW_WAITING = 30   # seconds before a "waiting" session is dropped (subagents resolve quickly)
# Hard ceiling a remote-control hook will block, in case the daemon dies. The
# daemon normally replies far sooner (at its idle timeout, or on answer); a
# client keepalive can extend up to this. Claude Code's own hook timeout is set
# just above it.
HOOK_WAIT_CEILING = 590

# ── Module-level state ────────────────────────────────────────────────────────

_verbose  = False
_shutdown = threading.Event()

_policy_lock: threading.Lock = threading.Lock()
_push_lock: threading.Lock = threading.Lock()
# session_id → {"state": "working"|"waiting", "time": float}

_ws_hub: CodelightWebsocketHub | None = None

# Remote control (armed via --remote-control, requires --secret):
# approve tool permissions AND answer AskUserQuestion prompts remotely.
_remote_permissions: bool = False
_remote_questions:   bool = False
_permission_timeout: int  = 60
_pending_requests = remote_control.PendingRequests()
_lock = _pending_requests.lock
_pending_perms = _pending_requests.permissions
_pending_questions = _pending_requests.questions
# GNOME answers over D-Bus (not a WS subscriber), so it announces its presence:
# question fall-through must not fire while a GNOME extension is listening.
GNOME_PRESENCE_TTL = 90
_gnome_last_seen: float = 0.0
_gnome_features: set = set()
# When a question-answering client was last connected, so a client that is
# merely reconnecting (e.g. VSCode restarting) isn't mistaken for "nobody home"
# and cut off before it re-subscribes.
_last_qclient_gone: float = 0.0
_log_lines:       collections.deque = collections.deque(maxlen=10)
_conversation_refresher: ConversationRefresher | None = None
_remote_manager: remote_control.RemoteRequestManager | None = None


class ConfigError(RuntimeError):
    pass


def _validate_config(data: object) -> dict:
    if not isinstance(data, dict):
        raise ConfigError("config.json must contain a JSON object")
    agents = data.get("agents", {})
    if not isinstance(agents, dict):
        raise ConfigError("config.json agents must contain a JSON object")
    for agent_id, section in agents.items():
        if not isinstance(agent_id, str) or not agent_id or not isinstance(section, dict):
            raise ConfigError("config.json agent entries must be named JSON objects")
        manage_hooks = section.get("manage_hooks")
        if manage_hooks is not None and not isinstance(manage_hooks, bool):
            raise ConfigError(f"config.json agents.{agent_id}.manage_hooks must be boolean")
    return data


def _load_config() -> dict:
    """~/.config/codelight/config.json — see companion/AGENTS.md for keys."""
    try:
        with open(os.path.join(CODELIGHT_CONFIG_HOME, "config.json")) as f:
            data = json.load(f)
        return _validate_config(data)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"could not read config.json: {exc}") from exc


_config = _load_config()


def _load_settings() -> dict:
    """Daemon-owned runtime settings (settings.json); {} if absent/unreadable."""
    try:
        with open(SETTINGS_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"[settings] could not read settings.json: {e}",
              file=sys.stderr, flush=True)
        return {}


def _persist_agent_budget(agent_id: str, budget: float) -> None:
    """Write an app-set budget into settings.json (agent-scoped), preserving
    other settings. Never touches the user's config.json."""
    settings = _load_settings()
    agents = settings.setdefault("agents", {})
    if not isinstance(agents, dict):
        agents = settings["agents"] = {}
    agents.setdefault(agent_id, {})
    if not isinstance(agents[agent_id], dict):
        agents[agent_id] = {}
    agents[agent_id]["monthly_budget_usd"] = budget
    os.makedirs(CODELIGHT_CONFIG_HOME, exist_ok=True)
    tmp = SETTINGS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(settings, f, indent=2)
    os.replace(tmp, SETTINGS_PATH)


def _apply_persisted_budgets() -> None:
    """On startup, apply app-set budgets (settings.json) over config defaults."""
    agents = _load_settings().get("agents")
    if not isinstance(agents, dict):
        return
    for agent_id, section in agents.items():
        if isinstance(section, dict) and "monthly_budget_usd" in section:
            try:
                _agents.set_budget(agent_id, float(section["monthly_budget_usd"]))
            except (TypeError, ValueError):
                pass


def _new_agent_registry(log=None) -> AgentRegistry:
    agents_config = _config.get("agents")
    sections = {
        agent_id: dict(section)
        for agent_id, section in agents_config.items()
    } if isinstance(agents_config, dict) else {}
    external_hooks = os.environ.get("CODELIGHT_EXTERNAL_HOOK_AGENTS", "")
    for agent_id in external_hooks.split(","):
        normalized = agent_id.strip().lower()
        if not normalized:
            continue
        sections.setdefault(normalized, {})["manage_hooks"] = False
    return AgentRegistry(
        agents_config=sections,
        log=log,
    )


_agents = _new_agent_registry()
AGENT_REGISTRY = _agents.display_registry()
DEFAULT_AGENT_ID = _agents.default_agent_id
_agent_process_probe = lifecycle.AgentProcessProbe(
    _agents.process_executables_by_agent(),
    process_matchers=_agents.process_matchers_by_agent())
_state = CodelightState(
    default_agent_id=DEFAULT_AGENT_ID,
    agent_registry=AGENT_REGISTRY,
    idle_window=IDLE_WINDOW,
    idle_window_waiting=IDLE_WINDOW_WAITING,
    agent_process_alive=_agent_process_probe,
    agent_process_states=_agent_process_probe.snapshot,
)
_power_status_publisher = power_status_file.PowerStatusPublisher(POWER_STATUS_PATH)
_lifecycle_evidence_store = lifecycle_evidence.LifecycleEvidenceStore(
    LIFECYCLE_EVIDENCE_PATH)
for _agent_id in _agents.supported_agent_ids():
    if _agents.session_reset_supported(_agent_id):
        _state.set_agent_capability(_agent_id, "session_reset_supported", True)

# ── Helpers ───────────────────────────────────────────────────────────────────

def vprint(*args, **kwargs):
    if _verbose:
        print(*args, **kwargs, flush=True)


def _log(msg: str) -> None:
    """Append a timestamped line to the rolling activity log.
    The terminal dashboard consumes this over the same client payload as every
    other surface."""
    ts = datetime.now().strftime("%H:%M:%S")
    _log_lines.append(f"[{ts}] {msg}")
    print(f"[{ts}] {msg}", flush=True)


def _normalize_agent_id(agent_id: str | None) -> str:
    return _state.normalize_agent_id(agent_id)


def _agent_display_name(agent_id: str | None) -> str:
    return _state.agent_display_name(agent_id)


def _restore_lifecycle_evidence(enabled_agents: set[str]) -> None:
    inventory_order = evidence_order(time.monotonic_ns(), UNKNOWN_RANK)
    live_by_agent = _agent_process_probe.identities(enabled_agents)
    if live_by_agent is None:
        failure_order = inventory_scan_failure_order(time.monotonic_ns())
        for agent_id in enabled_agents:
            _state.record_process_inventory(agent_id, None, failure_order)
            try:
                _lifecycle_evidence_store.invalidate_inventory_scan_failure(
                    agent_id,
                    failure_order.token,
                    failure_order.operation_id,
                )
            except (OSError, sqlite3.Error):
                pass
        return
    replay = _lifecycle_evidence_store.replay_inventory(
        live_by_agent,
        inventory_order,
    )
    providers = replay.providers
    stale_agents = replay.stale_inventory_agents
    for agent_id in enabled_agents:
        identities = live_by_agent.get(agent_id, frozenset())
        if agent_id in stale_agents:
            _state.record_process_inventory(agent_id, None)
            continue
        _state.record_process_inventory(
            agent_id,
            bool(identities),
            inventory_order,
        )
        if not identities:
            try:
                _lifecycle_evidence_store.clear_agent_invalidation(
                    agent_id,
                    inventory_order.token,
                    inventory_order.operation_id,
                )
            except (OSError, sqlite3.Error):
                _state.record_process_inventory(agent_id, None, inventory_order)
    replayed_by_agent: dict[str, list] = {
        agent_id: [] for agent_id in enabled_agents
    }
    for provider in providers:
        replayed_by_agent.setdefault(provider.agent_id, []).append(provider)
    for agent_id in enabled_agents:
        if agent_id in stale_agents:
            continue
        identities = live_by_agent.get(agent_id, frozenset())
        live_generations = frozenset(
            lifecycle.process_generation_key(agent_id, identity)
            for identity in identities
        )
        replayed_scopes = frozenset(
            lifecycle.authority_scope_key(
                agent_id,
                provider.identity,
                provider.scope_id,
            )
            for provider in replayed_by_agent.get(agent_id, [])
        )
        _state.reconcile_replayed_authority(
            agent_id,
            live_generations,
            replayed_scopes,
            inventory_order,
        )
    for provider in providers:
        authority_scope = lifecycle.authority_scope_key(
            provider.agent_id,
            provider.identity,
            provider.scope_id,
        )
        authority_generation = lifecycle.process_generation_key(
            provider.agent_id,
            provider.identity,
        )
        sessions = tuple(
            AuthoritySession(
                session.session_id,
                provider.agent_id,
                parse_session_state(session.state),
                session.observed_at,
                authority_scope,
                session.order_token,
                session.authority_rank,
                session.operation_id,
            )
            for session in provider.sessions
        )
        _state.update_provider_snapshot(
            sessions,
            agent_id=provider.agent_id,
            complete=provider.complete,
            observed_at=provider.observed_at,
            order_token=provider.order_token,
            authority_rank=provider.authority_rank,
            operation_id=provider.operation_id,
            authority_scope=authority_scope,
            authority_generation=authority_generation,
            lease_deadline_ns=provider.lease_deadline_ns,
            replayed=True,
        )


def _hook_process_identity(agent_id: str) -> lifecycle.ProcessIdentity | None:
    return _agent_process_probe.nearest_ancestor(agent_id, os.getpid())


def _broadcast(payload: dict) -> None:
    """Thread-safe push to all WebSocket clients and the D-Bus signal."""
    if _ws_hub is not None:
        _ws_hub.broadcast_status(payload)


# ── Session state ─────────────────────────────────────────────────────────────

def _update_session(session_id: str, state: str,
                    transcript: str = "", cwd: str = "",
                    agent_id: str = DEFAULT_AGENT_ID,
                    observed_at: float | None = None,
                    provider_evidence_complete: bool = True,
                    order_token: int | None = None,
                    authority_rank: int | None = None,
                    operation_id: str | None = None,
                    authority_scope: str = "",
                    authority_generation: str = "",
                    lease_deadline_ns: int | None = None) -> None:
    normalized_agent = _normalize_agent_id(agent_id)
    if not transcript:
        transcript = _agents.transcript_path_for_session(
            normalized_agent, session_id)
    _state.update_session(
        session_id,
        state,
        transcript=transcript,
        cwd=cwd,
        agent_id=normalized_agent,
        observed_at=observed_at,
        provider_evidence_complete=provider_evidence_complete,
        order_token=order_token,
        authority_rank=authority_rank,
        operation_id=operation_id,
        authority_scope=authority_scope,
        authority_generation=authority_generation,
        lease_deadline_ns=lease_deadline_ns,
    )


def _active_transcript() -> tuple[str, str, str]:
    """(session_id, transcript_path, agent_id) of the most-recently-active
    session that has a known transcript. Falls back to the last transcript we
    ever saw so the trailing message survives the session being popped on Stop.
    The agent id is carried alongside the path so the conversation label always
    matches the content shown."""
    active = _state.active_transcript()
    if active.path:
        return (active.session_id, active.path, active.agent_id)
    for agent_id, path in _agents.latest_transcript_fallbacks():
        if path:
            return (agent_id, path, agent_id)
    return ("", "", "")


def _client_config(client: str = "") -> dict:
    """One-time per-connection client config: agent branding and defaults.

    ``client`` is the requesting client's self-reported type (vscode/android/
    gnome/kde/screen/…); the screen gets bitmap logos instead of SVGs.
    """
    return {
        "default_agent_id": DEFAULT_AGENT_ID,
        "agents": _agents.client_metadata(client),
    }


def _parse_transcript(path: str, max_msgs: int = 60) -> list[dict]:
    return transcript_core.parse_transcript(
        path, tool_summary=_tool_summary,
        extractors=_agents.transcript_extractors(), max_msgs=max_msgs)


def _conversation_payload() -> dict | None:
    """Build the {"type":"conversation", ...} feed for the active session."""
    return conversation_core.build_payload(
        active_transcript=_active_transcript,
        parse_transcript=_parse_transcript,
        normalize_agent_id=_normalize_agent_id,
        agent_display_name=_agent_display_name,
    )


def _conversation_payload_for(agent_id: str) -> dict | None:
    """Build the conversation feed for a specific agent on client request —
    its active session's transcript, its newest one this run, or (cold start)
    the newest one on disk."""
    aid = _normalize_agent_id(agent_id)

    # Agents whose conversation lives behind an API/DB (e.g. OpenCode) supply a
    # provider that returns (session_id, lines) directly, bypassing the file+
    # extractor path.
    provider = _agents.conversation_provider_for(aid)
    if provider is not None:
        result = provider()
        if not result:
            return None
        session_id, lines = result
        display = _agent_display_name(aid)
        for line in lines:
            if isinstance(line, dict):
                line.setdefault("agent_id", aid)
                line.setdefault("agent_display", display)
        return {
            "type": "conversation",
            "session_id": session_id,
            "agent_id": aid,
            "agent_display": display,
            "lines": lines,
        }

    def resolve() -> tuple[str, str, str]:
        active = _state.transcript_for_agent(aid)
        if active.path:
            return (active.session_id, active.path, aid)
        return ("", _agents.latest_transcript_for(aid), aid)

    return conversation_core.build_payload(
        active_transcript=resolve,
        parse_transcript=_parse_transcript,
        normalize_agent_id=_normalize_agent_id,
        agent_display_name=_agent_display_name,
    )


def _active_conversation_path() -> str:
    return _active_transcript()[1]


def _has_conversation_clients() -> bool:
    return _ws_hub.has_conversation_clients() if _ws_hub is not None else False


def _conversation_refresh_thread() -> None:
    if _conversation_refresher is not None:
        _conversation_refresher.run()


def _notify_conversation_changed() -> None:
    if _conversation_refresher is not None:
        _conversation_refresher.notify()


def _broadcast_conversation() -> None:
    """Push the conversation feed to subscribed clients (thread-safe)."""
    if _ws_hub is not None:
        _ws_hub.broadcast_conversation()


def _overall_status() -> tuple[int, str, dict[str, str], str]:
    """Return (active_count, overall_status) from in-memory session state.
    Cleans up sessions that have been silent longer than IDLE_WINDOW."""
    # Sessions with a pending remote permission/question request stay alive —
    # the 30 s waiting window would otherwise drop them mid-request.
    return _state.overall_status(_pending_requests.pending_session_ids())


def _status_snapshot() -> dict:
    payload = _state.status_snapshot(_pending_requests.pending_session_ids())
    payload["power_authority"] = _state.power_authority_snapshot(
        _pending_requests.pending_session_ids()
    )
    payload["activity"] = list(_log_lines)
    payload["clients"] = {
        "websocket": _ws_hub.client_count() if _ws_hub is not None else 0,
        "dbus": _ws_hub.dbus_exported() if _ws_hub is not None else False,
    }
    return payload


# ── Remote permission approval ────────────────────────────────────────────────
#
# Flow: the PermissionRequest hook (--hook permission) blocks on the Unix
# socket; the daemon forwards the request to subscribed WS clients + D-Bus,
# and whoever answers first (VSCode / Android / GNOME) decides. On timeout the
# hook prints nothing and Claude Code falls back to its built-in prompt.
# Permission messages are only sent to clients that subscribed — old clients
# (ESP32 screen, older apps) never see them.

def _broadcast_rc(payload: dict, dbus_signal: str) -> None:
    """Send a remote-control event (permission/question) to subscribed WS
    clients and emit the named D-Bus signal."""
    if _ws_hub is not None:
        _ws_hub.broadcast_remote(payload, dbus_signal)


def _perm_request_payload(entry: dict) -> dict:
    cwd = str(entry.get("cwd") or "")
    tool_name = str(entry.get("tool_name") or "")
    can_allow_folder = bool(cwd) and (not _is_trusted_repo_cwd(cwd))
    can_allow_command = bool(cwd) and bool(entry.get("policy_command"))
    can_allow_tool = bool(tool_name) and tool_name != "?"
    return remote_payloads.permission_request_payload(
        {**entry, "agent_id": _normalize_agent_id(entry.get("agent_id"))},
        agent_display_name=_agent_display_name,
        allow_folder_available=can_allow_folder,
        allow_command_available=can_allow_command,
        allow_tool_available=can_allow_tool,
    )


def _resolve_permission(request_id: str, decision: str, by: str) -> bool:
    """Record a decision for a pending request. First response wins."""
    return _remote_request_manager().resolve_permission(request_id, decision, by)


# Grace window for a question to reach an answering client before it falls
# through to Claude's local dialog. Long enough to survive a client
# reconnecting (e.g. VSCode restart) — the daemon replays pending requests on
# subscribe — short enough that a truly unattended session isn't stuck waiting.
NO_CLIENT_GRACE = 6


RECONNECT_WINDOW = 30


def _extend_request(request_id: str) -> bool:
    """Client keepalive: reset a pending request's idle deadline (called while
    a remote client has the prompt open, so it never times out mid-interaction)."""
    return _remote_request_manager().extend(request_id)


def _cancel_permissions_for(session_id: str) -> None:
    """Session activity/end — wake up its pending permission AND question
    requests without a decision (answered locally)."""
    _remote_request_manager().cancel_for_session(session_id)


def _should_cancel_pending_for_hook(state: str, hook_event: str) -> bool:
    """Whether a lifecycle event proves a local prompt is no longer pending."""
    return remote_control.should_cancel_pending_for_hook(state, hook_event)


def _cancel_pending_for_hook(session_id: str, state: str,
                             hook_event: str) -> bool:
    if not _should_cancel_pending_for_hook(state, hook_event):
        return False
    _cancel_permissions_for(session_id)
    return True


def _register_permission(conn, msg: dict) -> None:
    """Take ownership of the hook's socket connection and start the approval
    round-trip. Called from the socket thread; must not block it."""
    _remote_request_manager().register_permission(conn, msg)


# ── Remote question answering via PreToolUse ──────────────────────────────────

def _question_request_payload(entry: dict) -> dict:
    return remote_payloads.question_request_payload(
        {**entry, "agent_id": _normalize_agent_id(entry.get("agent_id"))},
        agent_display_name=_agent_display_name,
    )


def _permission_resolved_payload(entry: dict, decision: str, by: str,
                                 persistence: dict | None) -> dict:
    return remote_payloads.permission_resolved_payload(
        {**entry, "agent_id": _normalize_agent_id(entry.get("agent_id"))},
        decision=decision,
        by=by,
        persistence=persistence,
        agent_display_name=_agent_display_name,
    )


def _question_resolved_payload(entry: dict, by: str) -> dict:
    return remote_payloads.question_resolved_payload(
        {**entry, "agent_id": _normalize_agent_id(entry.get("agent_id"))},
        by=by,
        agent_display_name=_agent_display_name,
    )


def _remote_request_manager() -> remote_control.RemoteRequestManager:
    global _remote_manager
    if _remote_manager is None:
        _remote_manager = remote_control.RemoteRequestManager(
            pending=_pending_requests,
            permission_timeout=lambda: _permission_timeout,
            remote_permissions=lambda: _remote_permissions,
            remote_questions=lambda: _remote_questions,
            normalize_agent_id=_normalize_agent_id,
            permission_payload=_perm_request_payload,
            question_payload=_question_request_payload,
            permission_resolved_payload=_permission_resolved_payload,
            question_resolved_payload=_question_resolved_payload,
            broadcast_remote=_broadcast_rc,
            report_status=lambda session_id, state, agent_id: _report_session(
                session_id, state, agent_id),
            push_status=_push,
            log=_log,
            allow_folder=_allow_folder,
            allow_command=_allow_command,
            allow_tool=_allow_tool,
            can_answer_questions=_can_answer_questions,
            last_question_client_gone=lambda: _last_qclient_gone,
            no_client_grace=NO_CLIENT_GRACE,
            reconnect_window=RECONNECT_WINDOW,
        )
    return _remote_manager


def _pending_remote_payloads() -> list[dict]:
    return _remote_request_manager().pending_payloads()


def _resolve_question(request_id: str, answers, by: str) -> bool:
    """Resolve a pending question. First response wins. A non-empty dict of
    {question: answer_string} answers it; an empty/None answers is an explicit
    skip (reply null → hook falls through to Claude's dialog immediately)."""
    return _remote_request_manager().resolve_question(request_id, answers, by)


def _gnome_present(feature: str) -> bool:
    """True if a GNOME extension announced it can answer `feature` recently."""
    return (time.time() - _gnome_last_seen < GNOME_PRESENCE_TTL
            and feature in _gnome_features)


def _announce_gnome(features: list[str]) -> bool:
    """Record a GNOME extension feature heartbeat received over D-Bus."""
    global _gnome_last_seen, _gnome_features
    _gnome_last_seen = time.time()
    _gnome_features = set(features)
    return True


def _can_answer_questions() -> bool:
    """True if any client (WS or GNOME) is currently able to answer questions."""
    ws_can_answer = _ws_hub.has_question_clients() if _ws_hub is not None else False
    return ws_can_answer or _gnome_present("questions")


def _note_qclient_gone() -> None:
    """Record that a question-answering WS client just disconnected, so a brief
    reconnect (VSCode restart) isn't mistaken for an unattended session."""
    global _last_qclient_gone
    _last_qclient_gone = time.time()


def _register_question(conn, msg: dict) -> None:
    """Take ownership of the hook's socket connection and start the answer
    round-trip for an AskUserQuestion PreToolUse hook."""
    _remote_request_manager().register_question(conn, msg)


# ── Permission policy compatibility helpers ──────────────────────────────────

def _is_trusted_repo_cwd(cwd: str) -> bool:
    return policy_core.is_trusted_repo_cwd(POLICY_PATH, cwd)


def _allow_folder(cwd: str) -> tuple[bool, str]:
    return policy_core.allow_folder(POLICY_PATH, _policy_lock, cwd)


def _allow_command(command: str, cwd: str) -> tuple[bool, str]:
    return policy_core.allow_command(POLICY_PATH, _policy_lock, command, cwd)


def _allow_tool(tool_name: str) -> tuple[bool, str]:
    return policy_core.allow_tool(POLICY_PATH, _policy_lock, tool_name)


def _tool_summary(tool_name: str, tool_input: dict) -> str:
    return policy_core.tool_summary(tool_name, tool_input)


# ── Hook mode ─────────────────────────────────────────────────────────────────

def run_hook(
    state: str,
    agent_id: str = DEFAULT_AGENT_ID,
    input_text: str | None = None,
) -> None:
    hook_commands.run_status_hook(
        state,
        agent_id=agent_id,
        socket_path=SOCKET_PATH,
        monitor_state_dir=MONITOR_STATE_DIR,
        normalize_agent_id=_normalize_agent_id,
        input_text=input_text,
        evidence_store=_lifecycle_evidence_store,
        process_identity=_hook_process_identity,
    )


def run_snapshot_hook(
    agent_id: str = DEFAULT_AGENT_ID,
    input_text: str | None = None,
) -> None:
    lifecycle_snapshot.run_snapshot_hook(
        agent_id=agent_id,
        socket_path=SOCKET_PATH,
        normalize_agent_id=_normalize_agent_id,
        evidence_store=_lifecycle_evidence_store,
        process_identity=_hook_process_identity,
        input_text=input_text,
    )


def run_permission_hook(wait_secs: int, mode, agent_id: str | None = None) -> None:
    hook_commands.run_permission_hook(
        mode=mode,
        agent_id=agent_id,
        auto_allow_tools=_agents.trusted_auto_allow_tools,
        socket_path=SOCKET_PATH,
        monitor_state_dir=MONITOR_STATE_DIR,
        policy_path=POLICY_PATH,
        policy_lock=_policy_lock,
        hook_wait_ceiling=HOOK_WAIT_CEILING,
        normalize_agent_id=_normalize_agent_id,
        agent_display_name=_agent_display_name,
    )


def run_question_hook(wait_secs: int, mode, agent_id: str | None = None) -> None:
    hook_commands.run_question_hook(
        mode=mode,
        agent_id=agent_id,
        socket_path=SOCKET_PATH,
        hook_wait_ceiling=HOOK_WAIT_CEILING,
        normalize_agent_id=_normalize_agent_id,
        agent_display_name=_agent_display_name,
    )

# ── Usage API ─────────────────────────────────────────────────────────────────
# Credentials are read fresh each poll so token rotations are picked up automatically.

def _usage_fetchers():
    # Use the shared registry (not a fresh one) so runtime-mutable state —
    # notably app-set/persisted budgets applied via _apply_persisted_budgets /
    # _set_budget — is reflected by the usage poller. A fresh registry would
    # rebuild agents from config.json (budget 0) and silently clear the meter
    # on the next poll.
    return _agents.usage_fetchers()


def _push_locked() -> None:
    authority = _state.power_authority_snapshot(
        _pending_requests.pending_session_ids()
    )
    try:
        _power_status_publisher.publish(authority)
    except OSError as exc:
        vprint(f"[power-status] write failed: {exc}")
    payload = _status_snapshot()
    _broadcast(payload)


def _push() -> None:
    """Build payload from current state and broadcast to all clients."""
    with _push_lock:
        _push_locked()


def _report_session(
    session_id: str,
    state: str,
    agent_id: str,
    *,
    transcript: str = "",
    cwd: str = "",
) -> None:
    with _push_lock:
        _update_session(
            session_id,
            state,
            transcript=transcript,
            cwd=cwd,
            agent_id=agent_id,
        )
        _push_locked()


def _consume_session_reset(agent_id: str, request_id: str = "") -> dict:
    aid = _state.normalize_agent_id(agent_id)
    result = _agents.consume_session_reset(aid)
    usage = result.get("usage")
    if isinstance(usage, dict):
        usage["session_reset_supported"] = True
        _state.update_usage(usages={aid: usage})
    elif _agents.session_reset_supported(aid):
        _state.set_agent_capability(aid, "session_reset_supported", True)
    payload = {
        "type": "session_reset_result",
        "id": request_id,
        "agent_id": aid,
        "agent_display": _state.agent_display_name(aid),
        "ok": bool(result.get("ok")),
        "outcome": str(result.get("outcome") or ""),
    }
    if result.get("message"):
        payload["message"] = str(result["message"])
    current_usage = _state.status_snapshot().get("per_agent_usage", {}).get(aid, {})
    reset_credits = current_usage.get("rateLimitResetCredits")
    if isinstance(reset_credits, dict):
        payload["rateLimitResetCredits"] = reset_credits
    _log(f"[reset] {aid} → {payload['outcome'] or 'unknown'}")
    _push()
    return payload


def _set_budget(agent_id: str, budget, request_id: str = "") -> dict:
    """Set an agent's usage-meter budget from a client, persist it, and refresh
    the meter. Mirrors the session-reset request/result contract."""
    aid = _state.normalize_agent_id(agent_id)
    try:
        value = max(0.0, float(budget))
    except (TypeError, ValueError):
        value = 0.0
    ok = _agents.set_budget(aid, value)
    if ok:
        _persist_agent_budget(aid, value)
        fetcher = _agents.usage_fetchers().get(aid)
        if fetcher is not None:
            _state.update_usage(usages={aid: fetcher()})
        _log(f"[budget] {aid} → ${value:.2f}")
        _push()
    return {
        "type": "budget_result",
        "id": request_id,
        "agent_id": aid,
        "agent_display": _state.agent_display_name(aid),
        "ok": ok,
        "budget_usd": _agents.get_budget(aid),
    }


def _send_prompt(agent_id: str, text, session_id: str = "",
                 request_id: str = "") -> dict:
    """Remote steering: forward a new instruction to an agent that has a
    control API (OpenCode). session_id targets the viewed session; empty means
    the active/latest one."""
    aid = _state.normalize_agent_id(agent_id)
    ok = _agents.send_prompt(aid, str(text or ""), str(session_id or ""))
    _log(f"[prompt] {aid} → {'sent' if ok else 'failed'}")
    return {
        "type": "send_prompt_result",
        "id": request_id,
        "agent_id": aid,
        "agent_display": _state.agent_display_name(aid),
        "ok": ok,
    }


def run_dashboard(host: str, ws_port: int, secret: str) -> None:
    """Run the terminal dashboard as a normal WebSocket client."""
    if not _have_websockets:
        print("[dashboard] websockets not installed — dashboard unavailable",
              file=sys.stderr)
        print("[dashboard] Install: pip install websockets", file=sys.stderr)
        return
    uri = f"ws://{host}:{ws_port}"
    try:
        asyncio.run(dashboard_client.run(
            uri=uri,
            secret=secret,
            agent_registry=AGENT_REGISTRY,
            default_agent_id=DEFAULT_AGENT_ID,
            websockets_module=_websockets,
        ))
    except KeyboardInterrupt:
        pass

# ── Daemon threads ────────────────────────────────────────────────────────────

def _ws_thread(port: int, secret: str, listen_host: str) -> None:
    """Run a WebSocket server; screen and Android clients connect here for live updates."""
    global _ws_hub

    if not _have_websockets:
        print("[ws] websockets not installed — clients unavailable", file=sys.stderr)
        print("[ws] Install: pip install websockets", file=sys.stderr)
        return

    _ws_hub = CodelightWebsocketHub(
        websockets_module=_websockets,
        shutdown=_shutdown,
        remote_permissions=lambda: _remote_permissions,
        remote_questions=lambda: _remote_questions,
        client_config=_client_config,
        status_snapshot=_status_snapshot,
        overall_status=_overall_status,
        pending_payloads=_pending_remote_payloads,
        conversation_payload=_conversation_payload,
        conversation_payload_for=_conversation_payload_for,
        notify_conversation_changed=_notify_conversation_changed,
        note_question_client_gone=_note_qclient_gone,
        respond_permission=_resolve_permission,
        respond_question=_resolve_question,
        consume_session_reset=_consume_session_reset,
        set_budget=_set_budget,
        send_prompt=_send_prompt,
        extend_request=_extend_request,
        announce_gnome=_announce_gnome,
        log=_log,
        verbose_log=vprint,
        listen_host=listen_host,
    )
    try:
        _ws_hub.run(port=port, secret=secret)
    finally:
        _ws_hub = None

def _mdns_thread(port: int, name: str, listen_host: str) -> None:
    discovery_core.advertise_mdns(
        port=port,
        name=name,
        address=listen_host,
        shutdown=_shutdown,
        log=_log,
        verbose_log=vprint,
    )


def _listen_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--listen-host requires an IP address") from exc
    if address.is_unspecified or address.is_multicast:
        raise argparse.ArgumentTypeError("--listen-host requires a specific interface address")
    if address.version == 6 and not address.is_loopback:
        raise argparse.ArgumentTypeError(
            "--listen-host supports IPv6 only for the loopback address"
        )
    return str(address)


def _should_advertise(listen_host: str) -> bool:
    return not ipaddress.ip_address(listen_host).is_loopback


def _handle_socket_message(conn, msg: dict) -> bool:
    """Handle one parsed Unix-socket hook message.

    Returns True when the handler takes ownership of the connection.
    """
    if msg.get("type") == "permission_request":
        _register_permission(conn, msg)
        return True
    if msg.get("type") == "question_request":
        _register_question(conn, msg)
        return True

    if "lifecycle_snapshot" in msg:
        snapshot_data = msg.get("lifecycle_snapshot")
        agent_id = _normalize_agent_id(
            msg.get("agent_id", DEFAULT_AGENT_ID)
        )
        snapshot = lifecycle_snapshot.parse_provider_snapshot(
            snapshot_data if isinstance(snapshot_data, dict) else {},
            agent_id,
        )
        observed_at_value = msg.get("observed_at")
        observed_at = (
            float(observed_at_value)
            if isinstance(observed_at_value, (int, float))
            and not isinstance(observed_at_value, bool)
            else time.time()
        )
        order_token_value = msg.get("order_token")
        order_token = (
            order_token_value
            if isinstance(order_token_value, int)
            and not isinstance(order_token_value, bool)
            else None
        )
        authority_rank_value = msg.get("authority_rank")
        authority_rank = (
            authority_rank_value
            if isinstance(authority_rank_value, int)
            and not isinstance(authority_rank_value, bool)
            and authority_rank_value in (0, 1, 2)
            else None
        )
        operation_id_value = msg.get("operation_id")
        operation_id = (
            operation_id_value
            if isinstance(operation_id_value, str) and operation_id_value
            else None
        )
        lease_deadline_value = msg.get("lease_deadline_ns")
        lease_deadline_ns = (
            lease_deadline_value
            if isinstance(lease_deadline_value, int)
            and not isinstance(lease_deadline_value, bool)
            else None
        )
        authority_scope_value = msg.get("authority_scope")
        authority_generation_value = msg.get("authority_generation")
        with _push_lock:
            _state.update_provider_snapshot(
                snapshot.sessions,
                agent_id=agent_id,
                complete=snapshot.complete,
                observed_at=observed_at,
                order_token=order_token,
                authority_rank=authority_rank,
                operation_id=operation_id,
                authority_scope=(
                    authority_scope_value
                    if isinstance(authority_scope_value, str)
                    else ""
                ),
                authority_generation=(
                    authority_generation_value
                    if isinstance(authority_generation_value, str)
                    else ""
                ),
                lease_deadline_ns=lease_deadline_ns,
            )
            _push_locked()
        return False

    sid = msg.get("session_id", "unknown")
    state = msg.get("state", "")

    if state:
        transcript_path = (
            msg.get("transcript_path")
            or msg.get("transcriptPath")
            or msg.get("transcript")
            or ""
        )
        with _push_lock:
            observed_at_value = msg.get("observed_at")
            observed_at = (
                float(observed_at_value)
                if isinstance(observed_at_value, (int, float))
                and not isinstance(observed_at_value, bool)
                else None
            )
            order_token_value = msg.get("order_token")
            order_token = (
                order_token_value
                if isinstance(order_token_value, int)
                and not isinstance(order_token_value, bool)
                else None
            )
            authority_rank_value = msg.get("authority_rank")
            authority_rank = (
                authority_rank_value
                if isinstance(authority_rank_value, int)
                and not isinstance(authority_rank_value, bool)
                and authority_rank_value in (0, 1, 2)
                else None
            )
            operation_id_value = msg.get("operation_id")
            operation_id = (
                operation_id_value
                if isinstance(operation_id_value, str) and operation_id_value
                else None
            )
            lease_deadline_value = msg.get("lease_deadline_ns")
            lease_deadline_ns = (
                lease_deadline_value
                if isinstance(lease_deadline_value, int)
                and not isinstance(lease_deadline_value, bool)
                else None
            )
            _update_session(sid, state,
                            transcript=transcript_path,
                            cwd=msg.get("cwd", ""),
                            agent_id=msg.get("agent_id", DEFAULT_AGENT_ID),
                            observed_at=observed_at,
                            order_token=order_token,
                            authority_rank=authority_rank,
                            operation_id=operation_id,
                            authority_scope=(
                                msg.get("authority_scope")
                                if isinstance(msg.get("authority_scope"), str)
                                else ""
                            ),
                            authority_generation=(
                                msg.get("authority_generation")
                                if isinstance(msg.get("authority_generation"), str)
                                else ""
                            ),
                            lease_deadline_ns=lease_deadline_ns,
                            provider_evidence_complete=(
                                msg.get("provider_evidence_complete") is not False
                            ))
            # PreToolUse status and question hooks may run concurrently.
            # Only completion events prove a local prompt is finished.
            hook_event = str(msg.get("hook_event") or "")
            _cancel_pending_for_hook(sid, state, hook_event)
            # Session-scoped tool allowances die with the session — not on Stop,
            # which fires at every turn end.
            if hook_event == "SessionEnd":
                _remote_request_manager().clear_session_allowances(sid)
            vprint(f"[socket] {sid[:8]}… → {state}")
            _push_locked()
        # The transcript just grew — refresh the conversation feed.
        _notify_conversation_changed()
    return False


def _socket_thread() -> None:
    """Accept hook events on the Unix socket and broadcast to clients immediately."""
    socket_server.serve_hook_socket(
        socket_path=SOCKET_PATH,
        shutdown=_shutdown,
        handle_message=_handle_socket_message,
        log=vprint,
    )


def _usage_thread() -> None:
    """Refresh supported-agent usage and broadcast after each update."""
    UsagePoller(
        state=_state,
        fetchers=_usage_fetchers(),
        interval=USAGE_INTERVAL,
        shutdown=_shutdown,
        log=_log,
        push=_push,
    ).run()


def _power_status_thread(enabled_agents: set[str] | None = None) -> None:
    while not _shutdown.is_set():
        if enabled_agents is not None:
            _restore_lifecycle_evidence(enabled_agents)
        _push()
        _shutdown.wait(POWER_STATUS_INTERVAL)


def _background_listener_context() -> agents_base.ListenerContext:
    """Daemon capabilities for a hookless agent's event-stream listener: report
    status like a hook, and route permission/question prompts through the same
    remote-control manager (the listener supplies its own transport responder)."""
    mgr = _remote_request_manager()
    return agents_base.ListenerContext(
        shutdown=_shutdown,
        report_status=lambda session_id, state, agent_id, cwd="":
            _report_session(session_id, state, agent_id, cwd=cwd),
        submit_permission=lambda msg, responder:
            mgr.register_permission(None, msg, responder=responder),
        submit_question=lambda msg, responder:
            mgr.register_question(None, msg, responder=responder),
        cancel_session_prompts=_cancel_permissions_for,
        log=vprint,
        notify_conversation_changed=_notify_conversation_changed,
    )


def _run_background_listener(agent_id: str, listener) -> None:
    ctx = _background_listener_context()
    try:
        listener(ctx)
    except Exception as exc:  # never let one listener take down its thread quietly
        vprint(f"[{agent_id}] listener stopped: {exc}")


# ── Uninstall ─────────────────────────────────────────────────────────────────

def uninstall() -> None:
    """Remove all codelight hooks, socket file, and state directory."""
    lifecycle.uninstall(
        agent_registry=_new_agent_registry(),
        policy_path=POLICY_PATH,
        config_home=CODELIGHT_CONFIG_HOME,
        socket_path=SOCKET_PATH,
        monitor_state_dir=MONITOR_STATE_DIR,
    )


def _parse_agent_set(value: str | None) -> set[str]:
    return lifecycle.parse_agent_set(value, set(AGENT_REGISTRY))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global _verbose, _conversation_refresher

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        nargs="?",
        choices=["dashboard", "status", "hook"],
        help="Run the dashboard, print power status, or receive a legacy hook.",
    )
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove codelight agent hooks and delete state files.")
    parser.add_argument("--install", action="store_true",
                        help="Install and start a user service — systemd on "
                             "Linux, launchd on macOS (requires --name).")
    parser.add_argument("--hook", metavar="STATE",
                        help="Hook mode: send STATE event to daemon and exit. "
                             "Used internally by agent hooks (working/waiting/ended).")
    parser.add_argument("--agent", default=DEFAULT_AGENT_ID,
                        help="Internal hook/runtime agent id ("
                             + "/".join(AGENT_REGISTRY) + ").")
    parser.add_argument("--provider", default="", help=argparse.SUPPRESS)
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show low-level debug events (socket, API) in activity log")
    parser.add_argument("--ws-port", type=int, default=8765,
                        help="WebSocket port for clients (default: 8765)")
    parser.add_argument(
        "--listen-host",
        type=_listen_address,
        default=DEFAULT_LISTEN_HOST,
        help="Specific WebSocket interface address (default: 127.0.0.1)",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="With 'dashboard': daemon host (default: 127.0.0.1)")
    parser.add_argument("--name", default=None,
                        help="mDNS service name visible to clients (required)")
    parser.add_argument("--secret", default="",
                        help="Shared secret for WebSocket auth (match in screen config)")
    parser.add_argument("--remote-control", action="store_true",
                        help="Let clients remotely approve agent permission prompts "
                             "and answer supported question prompts. "
                             "Requires --secret.")
    parser.add_argument("--permission-timeout", type=int, default=60,
                        help="Seconds to wait for a remote decision/answer before "
                             "falling back to the agent's built-in prompt (default: 60)")
    parser.add_argument("--agents", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--vscode", action="store_true",
                        help="With --install: also install the codelight VSCode "
                             "extension from the latest GitHub release")
    args = parser.parse_args()

    if args.command == "dashboard":
        run_dashboard(args.host, args.ws_port, args.secret)
        return

    if args.command == "status":
        json.dump(power_status_file.read_power_status(POWER_STATUS_PATH), sys.stdout)
        sys.stdout.write("\n")
        return

    if args.command == "hook":
        input_text = sys.stdin.read()
        data = hook_runtime.parse_json_object(input_text)
        run_hook(
            hook_commands.legacy_status_state(data),
            agent_id=args.provider or args.agent,
            input_text=input_text,
        )
        return

    if args.uninstall:
        uninstall()
        return

    if args.install:
        if args.name is None:
            parser.error("--name is required with --install")
        if args.remote_control and not args.secret:
            parser.error("--remote-control requires --secret (remote approval/answers "
                         "are code-execution capability and must not be open to the LAN)")
        detected_agents = lifecycle.detect_installed_agents(_new_agent_registry())
        enabled_agents = (
            _parse_agent_set(args.agents)
            if args.agents is not None
            else detected_agents
        )
        print("[install] detected agents: "
              + (", ".join(sorted(detected_agents)) or "none"))
        lifecycle.install_service(
            script_path=invocation.self_invocation()[1],
            name=args.name,
            secret=args.secret,
            ws_port=args.ws_port,
            listen_host=args.listen_host,
            verbose=args.verbose,
            remote_control=args.remote_control,
            permission_timeout=args.permission_timeout,
            agents=enabled_agents,
        )
        if args.vscode:
            lifecycle.install_vscode_extension(
                invocation.self_invocation()[1], args.secret, args.ws_port)
        return

    if args.hook:
        if args.hook == "snapshot":
            run_snapshot_hook(args.agent, input_text=sys.stdin.read())
            return
        hook_mode = _agents.hook_modes().get(args.hook)
        if hook_mode is None:
            run_hook(args.hook, agent_id=args.agent)
        elif hook_mode.kind == "permission":
            run_permission_hook(args.permission_timeout, hook_mode,
                                agent_id=args.agent)
        else:
            run_question_hook(args.permission_timeout, hook_mode,
                              agent_id=args.agent)
        return

    if args.name is None:
        parser.error("--name is required (e.g. --name henrik-laptop). "
                     "It identifies this daemon to clients.")

    _verbose = args.verbose

    global _remote_permissions, _remote_questions, _permission_timeout
    _permission_timeout = args.permission_timeout
    _remote_permissions = args.remote_control
    _remote_questions   = args.remote_control
    if args.remote_control and not args.secret:
        print("[rc] --remote-control requires --secret — feature disabled",
              file=sys.stderr, flush=True)
        _remote_permissions = _remote_questions = False

    enabled_agents = (_parse_agent_set(args.agents)
                      if args.agents is not None
                      else lifecycle.detect_installed_agents(_new_agent_registry()))
    print("[agents] enabled: " + (", ".join(sorted(enabled_agents)) or "none"),
          flush=True)
    # Keep configured agents visible (idle) even when they have no usage meter
    # and no active session — otherwise hook-only agents like Cursor/Grok only
    # appear while actively working.
    _state.set_enabled_agents(enabled_agents)
    _restore_lifecycle_evidence(enabled_agents)
    _apply_persisted_budgets()

    lifecycle.install_agent_hooks(
        agent_registry=_new_agent_registry(log=vprint),
        enabled_agents=enabled_agents,
        script_path=invocation.self_invocation()[1],
        hook_wait_ceiling=HOOK_WAIT_CEILING,
        remote_permissions=_remote_permissions,
        remote_questions=_remote_questions,
        permission_timeout=_permission_timeout,
        log=vprint,
    )

    print(f"codelight  [ws://{args.listen_host}:{args.ws_port}]  (Ctrl-C to stop)", flush=True)

    _conversation_refresher = ConversationRefresher(
        active_path=_active_conversation_path,
        has_clients=_has_conversation_clients,
        broadcast=_broadcast_conversation,
        shutdown=_shutdown,
    )

    threading.Thread(target=_socket_thread, daemon=True).start()
    threading.Thread(target=_usage_thread,  daemon=True).start()
    threading.Thread(
        target=_power_status_thread,
        args=(set(enabled_agents),),
        daemon=True,
    ).start()
    threading.Thread(target=_conversation_refresh_thread, daemon=True).start()

    threading.Thread(
        target=_ws_thread,
        args=(args.ws_port, args.secret, args.listen_host),
        daemon=True,
    ).start()

    if _should_advertise(args.listen_host):
        threading.Thread(
            target=_mdns_thread,
            args=(args.ws_port, args.name, args.listen_host),
            daemon=True,
        ).start()

    for _agent_id, _listener in _agents.background_listeners(enabled_agents).items():
        threading.Thread(
            target=_run_background_listener,
            args=(_agent_id, _listener),
            daemon=True,
        ).start()
        print(f"[{_agent_id}] background listener started", flush=True)

    print(f"daemon ready — next usage poll in {USAGE_INTERVAL}s", flush=True)

    signal.signal(signal.SIGTERM, lambda *_: (_shutdown.set(), sys.exit(0)))

    try:
        while not _shutdown.is_set():
            _shutdown.wait(1.0)
    except KeyboardInterrupt:
        _shutdown.set()


if __name__ == "__main__":
    main()
