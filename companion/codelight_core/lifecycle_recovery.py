from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence

from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_inventory import SqlValue, row_order


def recover_agent_floors(
    connection: sqlite3.Connection,
    rows: Sequence[tuple[SqlValue, ...]],
    *,
    live: Mapping[tuple[str, int, str, str], ProcessIdentity],
    invalidations: Mapping[str, EvidenceOrder],
    inventory_order: EvidenceOrder | None,
    now_order_token: int,
) -> dict[str, int]:
    floors = {
        str(row[0]): int(row[1])
        for row in connection.execute('SELECT agent_id, order_token FROM agent_recovery_floors')
    }
    if inventory_order is None:
        return floors
    claims: dict[tuple[str, int, str, str], int] = {}
    for row in rows:
        pid, deadline = row[1], row[10]
        if not isinstance(pid, int) or not isinstance(deadline, int):
            continue
        key = (str(row[0]), pid, str(row[3]), str(row[4]))
        if (
            key in live and row[11] == 1
            and deadline >= now_order_token
            and row_order(row, 7) == row_order(row, 12)
        ):
            claims[key] = max(claims.get(key, 0), row_order(row, 12).token)
    for agent_id, invalidation in invalidations.items():
        generations = [key for key in live if key[0] == agent_id]
        if not generations or any(key not in claims for key in generations):
            continue
        floor = min(inventory_order.token, *(claims[key] for key in generations))
        if floor <= invalidation.token:
            continue
        connection.execute('''INSERT INTO agent_recovery_floors VALUES (?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET order_token = max(order_token, excluded.order_token)
        ''', (agent_id, floor))
        floors[agent_id] = max(floors.get(agent_id, 0), floor)
    return floors
