from __future__ import annotations

import sqlite3

from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity


def provider_values(
    agent_id: str,
    identity: ProcessIdentity,
    scope_id: str,
    observed_at: float,
    order: EvidenceOrder,
    snapshot_order: EvidenceOrder,
    lease_deadline_ns: int,
    complete: bool,
) -> tuple[str | int | float, ...]:
    return (
        agent_id,
        identity.pid,
        identity.ppid,
        identity.started_at,
        identity.executable,
        scope_id,
        observed_at,
        order.token,
        order.authority_rank,
        order.operation_id,
        snapshot_order.token,
        snapshot_order.authority_rank,
        snapshot_order.operation_id,
        lease_deadline_ns,
        int(complete),
    )


def clear_scope_invalidation(
    connection: sqlite3.Connection,
    agent_id: str,
    identity: ProcessIdentity,
    scope_id: str,
    order: EvidenceOrder,
) -> None:
    connection.execute(
        """
        DELETE FROM scope_invalidations
        WHERE agent_id = ? AND pid = ? AND started_at = ? AND scope_id = ?
          AND operation_id = ?
        """,
        (
            agent_id,
            identity.pid,
            identity.started_at,
            scope_id,
            order.operation_id,
        ),
    )


def clear_scope_invalidations_through(
    connection: sqlite3.Connection,
    agent_id: str,
    identity: ProcessIdentity,
    scope_id: str,
    order: EvidenceOrder,
) -> None:
    connection.execute(
        """
        DELETE FROM scope_invalidations
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
