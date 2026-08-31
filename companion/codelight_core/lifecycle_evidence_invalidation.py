from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass

from codelight_core.evidence_order import (
    INVENTORY_SCAN_FAILURE_OPERATION_PREFIX,
    EvidenceOrder,
)
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_taint import (
    GenerationTaintStore,
)
from codelight_core.lifecycle_evidence_taint_io import TaintOperation


@dataclass(frozen=True, slots=True)
class ScopeWrite:
    agent_id: str
    identity: ProcessIdentity
    scope_id: str
    order: EvidenceOrder


class LifecycleInvalidations:
    def __init__(
        self,
        connect: Callable[[], sqlite3.Connection],
        taints: GenerationTaintStore,
    ) -> None:
        self._connect = connect
        self._taints = taints

    def invalidate_agent(self, agent_id: str, order: EvidenceOrder) -> None:
        sidecar_written = True
        try:
            self._taints.mark_agent(agent_id, order)
        except OSError:
            sidecar_written = False
        if sidecar_written:
            return
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO agent_invalidations (
                    agent_id, order_token, authority_rank, operation_id
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(agent_id, operation_id) DO UPDATE SET
                    order_token = excluded.order_token,
                    authority_rank = excluded.authority_rank
                WHERE (
                    excluded.order_token,
                    excluded.authority_rank
                ) > (
                    agent_invalidations.order_token,
                    agent_invalidations.authority_rank
                )
                """,
                (
                    agent_id,
                    order.token,
                    order.authority_rank,
                    order.operation_id,
                ),
            )

    def clear_agent(self, agent_id: str, order: EvidenceOrder) -> None:
        self._taints.clear_agent_before(agent_id, order)
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                DELETE FROM agent_invalidations
                WHERE agent_id = ?
                  AND order_token < ?
                """,
                (
                    agent_id,
                    order.token,
                ),
            )

    def clear_inventory_scan_failures_before(
        self,
        agent_id: str,
        order: EvidenceOrder,
    ) -> None:
        self._taints.clear_inventory_scan_failures_before(agent_id, order)
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                DELETE FROM agent_invalidations
                WHERE agent_id = ?
                  AND order_token < ?
                  AND substr(operation_id, 1, ?) = ?
                """,
                (
                    agent_id,
                    order.token,
                    len(INVENTORY_SCAN_FAILURE_OPERATION_PREFIX),
                    INVENTORY_SCAN_FAILURE_OPERATION_PREFIX,
                ),
            )

    def begin_scope_write(self, write: ScopeWrite) -> TaintOperation | None:
        try:
            sidecar = self._taints.mark(
                write.agent_id,
                write.identity,
                write.scope_id,
                write.order,
            )
        except OSError:
            sidecar = None
        if sidecar is not None:
            return sidecar
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO scope_invalidations (
                    agent_id, pid, started_at, scope_id,
                    order_token, authority_rank, operation_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    write.agent_id,
                    write.identity.pid,
                    write.identity.started_at,
                    write.scope_id,
                    write.order.token,
                    write.order.authority_rank,
                    write.order.operation_id,
                ),
            )
        return None
