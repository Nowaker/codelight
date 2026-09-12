from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass

from codelight_core import hook_io
from codelight_core import hook_runtime
from codelight_core.evidence_order import authority_rank_for_snapshot, evidence_order
from codelight_core.lifecycle import (
    ProcessIdentity,
    authority_scope_key,
    process_generation_key,
)
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.power_authority import AuthoritySession, parse_session_state


ProcessIdentityCallback = Callable[[str], ProcessIdentity | None]
AgentNameCallback = Callable[[str | None], str]
_SNAPSHOT_STATES = frozenset({"working", "waiting", "idle"})
_ACTIVE_SNAPSHOT_STATES = frozenset({"working", "waiting"})
_SNAPSHOT_LEASE_NS = 45 * 1_000_000_000
_NO_EXPIRY_NS = 9_223_372_036_854_775_807


@dataclass(frozen=True, slots=True)
class ProviderSnapshot:
    complete: bool
    sessions: tuple[AuthoritySession, ...]


def snapshot_lease_deadline_ns(
    snapshot: ProviderSnapshot,
    order_token: int,
) -> int:
    if snapshot.complete and not any(
        session.state in _ACTIVE_SNAPSHOT_STATES
        for session in snapshot.sessions
    ):
        return _NO_EXPIRY_NS
    return order_token + _SNAPSHOT_LEASE_NS


def parse_provider_snapshot(data: dict, agent_id: str) -> ProviderSnapshot:
    complete = data.get("complete") is True
    raw_sessions = data.get("sessions")
    if not isinstance(raw_sessions, list):
        return ProviderSnapshot(False, ())

    sessions = []
    session_ids = set()
    for raw_session in raw_sessions:
        if not isinstance(raw_session, dict):
            return ProviderSnapshot(False, ())
        session_id_value = raw_session.get("session_id")
        state_value = raw_session.get("state")
        if (
            not isinstance(session_id_value, str)
            or not session_id_value
            or not isinstance(state_value, str)
            or state_value not in _SNAPSHOT_STATES
            or session_id_value in session_ids
        ):
            return ProviderSnapshot(False, ())
        session_ids.add(session_id_value)
        sessions.append(
            AuthoritySession(
                session_id_value,
                agent_id,
                parse_session_state(state_value),
            )
        )
    return ProviderSnapshot(complete, tuple(sessions))


def run_snapshot_hook(
    *,
    agent_id: str,
    socket_path: str,
    normalize_agent_id: AgentNameCallback,
    evidence_store: LifecycleEvidenceStore,
    process_identity: ProcessIdentityCallback,
    input_text: str | None = None,
) -> None:
    data = hook_runtime.parse_json_object(input_text or "")
    normalized_agent = normalize_agent_id(agent_id)
    snapshot = parse_provider_snapshot(data, normalized_agent)
    observed_at = time.time()
    operation = evidence_order(
        time.monotonic_ns(),
        authority_rank_for_snapshot(
            tuple(session.state for session in snapshot.sessions),
            snapshot.complete,
        ),
    )
    lease_deadline_ns = snapshot_lease_deadline_ns(snapshot, operation.token)
    cwd_value = data.get("cwd")
    scope_id = (
        os.path.realpath(cwd_value)
        if isinstance(cwd_value, str) and cwd_value
        else ""
    )
    identity = process_identity(normalized_agent)
    evidence_persisted = False
    try:
        if identity is None:
            evidence_store.invalidate_agent(
                normalized_agent,
                operation.token,
                operation.operation_id,
            )
        else:
            evidence_store.record_snapshot(
                agent_id=normalized_agent,
                identity=identity,
                sessions=snapshot.sessions,
                complete=snapshot.complete,
                observed_at=observed_at,
                scope_id=scope_id,
                order_token=operation.token,
                authority_rank=operation.authority_rank,
                operation_id=operation.operation_id,
                lease_deadline_ns=lease_deadline_ns,
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
    complete = snapshot.complete and evidence_persisted and identity is not None

    hook_io.send_json(
        socket_path,
        {
            "agent_id": normalized_agent,
            "cwd": cwd_value if isinstance(cwd_value, str) else "",
            "hook_event": str(data.get("hook_event_name") or ""),
            "observed_at": observed_at,
            "order_token": operation.token,
            "authority_rank": operation.authority_rank,
            "operation_id": operation.operation_id,
            "lease_deadline_ns": lease_deadline_ns,
            "authority_scope": authority_scope,
            "authority_generation": authority_generation,
            "boot_id": evidence_store.boot_id,
            "lifecycle_snapshot": {
                "complete": complete,
                "sessions": [
                    {
                        "session_id": session.session_id,
                        "state": session.state,
                    }
                    for session in snapshot.sessions
                ],
            },
        },
        timeout=0.5,
    )
