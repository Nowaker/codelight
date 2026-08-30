from __future__ import annotations

import sqlite3

from codelight_core.evidence_order import (
    EvidenceOrder,
    authority_rank_for_state,
)
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_sql import (
    clear_scope_invalidation,
    clear_scope_invalidations_through,
    provider_values,
)
from codelight_core.power_authority import AuthoritySession


def _session_order(
    session: AuthoritySession,
    fallback: EvidenceOrder,
) -> EvidenceOrder:
    if session.order_token is None:
        return fallback
    rank = session.authority_rank
    if rank is None:
        rank = authority_rank_for_state(session.state, True)
    operation_id = session.operation_id or fallback.operation_id
    return EvidenceOrder(session.order_token, rank, operation_id)


def write_snapshot(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    identity: ProcessIdentity,
    scope_id: str,
    sessions: tuple[AuthoritySession, ...],
    complete: bool,
    observed_at: float,
    order: EvidenceOrder,
    lease_deadline_ns: int,
    sidecar: bool,
) -> None:
    cursor = connection.execute(
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
            snapshot_order_token = CASE
                WHEN excluded.complete = 1 THEN excluded.snapshot_order_token
                ELSE provider_evidence.snapshot_order_token
            END,
            snapshot_authority_rank = CASE
                WHEN excluded.complete = 1 THEN excluded.snapshot_authority_rank
                ELSE provider_evidence.snapshot_authority_rank
            END,
            snapshot_operation_id = CASE
                WHEN excluded.complete = 1 THEN excluded.snapshot_operation_id
                ELSE provider_evidence.snapshot_operation_id
            END,
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
            order if complete else EvidenceOrder(0, 0, ""),
            lease_deadline_ns,
            complete,
        ),
    )
    if cursor.rowcount > 0 and complete:
        connection.execute(
            """
            DELETE FROM session_evidence
            WHERE agent_id = ? AND pid = ? AND started_at = ? AND scope_id = ?
              AND (order_token, authority_rank, operation_id) <= (?, ?, ?)
            """,
            (
                agent_id,
                identity.pid,
                identity.started_at,
                scope_id,
                order.token,
                order.authority_rank,
                order.operation_id,
            ),
        )
        for session in sessions:
            session_order = _session_order(session, order)
            connection.execute(
                """
                INSERT INTO session_evidence VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'snapshot'
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
                    session.session_id,
                    session.state,
                    session.observed_at
                    if session.observed_at is not None
                    else observed_at,
                    session_order.token,
                    session_order.authority_rank,
                    session_order.operation_id,
                ),
            )
    if complete:
        clear_scope_invalidations_through(
            connection,
            agent_id,
            identity,
            scope_id,
            order,
        )
    elif not sidecar:
        clear_scope_invalidation(
            connection,
            agent_id,
            identity,
            scope_id,
            order,
        )
