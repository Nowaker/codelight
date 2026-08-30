from __future__ import annotations

import sqlite3

from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_sql import (
    clear_scope_invalidation,
    provider_values,
)


def write_event(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    identity: ProcessIdentity,
    scope_id: str,
    session_id: str,
    state: str,
    observed_at: float,
    order: EvidenceOrder,
    lease_deadline_ns: int,
    hook_event: str,
    complete: bool,
    sidecar: bool,
) -> None:
    connection.execute(
        """
        INSERT INTO provider_evidence VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        ON CONFLICT(agent_id, pid, started_at, scope_id) DO UPDATE SET
            ppid = excluded.ppid,
            executable = excluded.executable,
            observed_at = excluded.observed_at,
            order_token = excluded.order_token,
            authority_rank = excluded.authority_rank,
            operation_id = excluded.operation_id,
            lease_deadline_ns = excluded.lease_deadline_ns,
            complete = excluded.complete
        WHERE (
            excluded.order_token,
            excluded.authority_rank,
            excluded.operation_id
        ) >= (
            provider_evidence.order_token,
            provider_evidence.authority_rank,
            provider_evidence.operation_id
        )
        """,
        provider_values(
            agent_id,
            identity,
            scope_id,
            observed_at,
            order,
            EvidenceOrder(0, 0, ""),
            lease_deadline_ns,
            complete,
        ),
    )
    provider = connection.execute(
        """
        SELECT snapshot_order_token, snapshot_authority_rank,
               snapshot_operation_id
        FROM provider_evidence
        WHERE agent_id = ? AND pid = ? AND started_at = ? AND scope_id = ?
        """,
        (agent_id, identity.pid, identity.started_at, scope_id),
    ).fetchone()
    snapshot_order = EvidenceOrder(0, 0, "")
    if provider is not None:
        snapshot_order = EvidenceOrder(
            int(provider[0]),
            int(provider[1]),
            str(provider[2]),
        )
    if order >= snapshot_order:
        connection.execute(
            """
            INSERT INTO session_evidence VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(agent_id, pid, started_at, scope_id, session_id)
            DO UPDATE SET
                state = excluded.state,
                observed_at = excluded.observed_at,
                order_token = excluded.order_token,
                authority_rank = excluded.authority_rank,
                operation_id = excluded.operation_id,
                hook_event = excluded.hook_event
            WHERE (
                excluded.order_token,
                excluded.authority_rank,
                excluded.operation_id
            ) >= (
                session_evidence.order_token,
                session_evidence.authority_rank,
                session_evidence.operation_id
            )
            """,
            (
                agent_id,
                identity.pid,
                identity.started_at,
                scope_id,
                session_id,
                state,
                observed_at,
                order.token,
                order.authority_rank,
                order.operation_id,
                hook_event,
            ),
        )
    if not sidecar:
        clear_scope_invalidation(
            connection,
            agent_id,
            identity,
            scope_id,
            order,
        )
