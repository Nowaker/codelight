from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
import sqlite3
import time

from codelight_core.lifecycle import ProcessIdentity, authority_scope_key, process_generation_key
from codelight_core.lifecycle_evidence_inventory import SqlValue, row_order
from codelight_core.lifecycle_evidence_taint import GenerationTaintStore


@dataclass(frozen=True, slots=True)
class SnapshotScope:
    agent_id: str
    scope: str
    generation: str
    boot_id: str = ""


def corroborates_snapshot(connect: Callable[[], sqlite3.Connection], taints: GenerationTaintStore, claim: SnapshotScope) -> bool:
    if not claim.scope or not claim.generation or not claim.boot_id:
        return False
    try:
        with closing(connect()) as connection:
            connection.execute("BEGIN")
            attempts, malformed = taints.attempts()
            if malformed:
                return False
            floor_row: tuple[int] | None = connection.execute(
                "SELECT order_token FROM agent_recovery_floors WHERE agent_id=?", (claim.agent_id,),
            ).fetchone()
            floor = floor_row[0] if floor_row is not None else 0
            if any(attempt.agent_id == claim.agent_id
                   and (attempt.identity is not None or attempt.order.token >= floor) for attempt in attempts):
                return False
            if connection.execute(
                """SELECT 1 FROM agent_invalidations WHERE agent_id=? AND order_token>=?
                   UNION ALL SELECT 1 FROM scope_invalidations WHERE agent_id=? LIMIT 1""",
                (claim.agent_id, floor, claim.agent_id),
            ).fetchone() is not None:
                return False
            rows: list[tuple[SqlValue, ...]] = connection.execute(
                """SELECT pid,ppid,started_at,executable,scope_id,lease_deadline_ns,complete,
                          order_token,authority_rank,operation_id,
                          snapshot_order_token,snapshot_authority_rank,snapshot_operation_id
                   FROM provider_evidence WHERE agent_id=?""", (claim.agent_id,),
            ).fetchall()
        now = time.monotonic_ns()
        for row in rows:
            pid, ppid, started, executable, scope, deadline, complete = row[:7]
            if not (
                isinstance(pid, int) and isinstance(ppid, int)
                and isinstance(started, str) and isinstance(executable, str)
                and isinstance(scope, str) and isinstance(deadline, int)
                and complete == 1 and deadline > now
            ):
                continue
            snapshot = row_order(row, 10)
            if snapshot.token <= 0 or row_order(row, 7) != snapshot:
                continue
            identity = ProcessIdentity(pid, ppid, started, executable, executable, claim.boot_id)
            if (process_generation_key(claim.agent_id, identity) == claim.generation
                    and authority_scope_key(claim.agent_id, identity, scope) == claim.scope):
                return True
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return False
    return False
