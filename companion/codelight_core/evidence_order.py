from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Final


IDLE_RANK = 0
UNKNOWN_RANK = 1
ACTIVE_RANK = 2
INVENTORY_SCAN_FAILURE_OPERATION_PREFIX: Final = "inventory-scan-failed-"


@dataclass(frozen=True, order=True, slots=True)
class EvidenceOrder:
    token: int
    authority_rank: int
    operation_id: str


def authority_rank_for_state(state: str, complete: bool) -> int:
    if state in ("working", "waiting"):
        return ACTIVE_RANK
    if not complete or state == "unknown":
        return UNKNOWN_RANK
    return IDLE_RANK


def authority_rank_for_snapshot(states: tuple[str, ...], complete: bool) -> int:
    if any(state in ("working", "waiting") for state in states):
        return ACTIVE_RANK
    return IDLE_RANK if complete else UNKNOWN_RANK


def evidence_order(
    token: int,
    authority_rank: int,
    operation_id: str | None = None,
) -> EvidenceOrder:
    return EvidenceOrder(token, authority_rank, operation_id or uuid.uuid4().hex)


def inventory_scan_failure_order(
    token: int,
    operation_id: str | None = None,
) -> EvidenceOrder:
    source_operation_id = operation_id or uuid.uuid4().hex
    tagged_operation_id = (
        source_operation_id
        if source_operation_id.startswith(INVENTORY_SCAN_FAILURE_OPERATION_PREFIX)
        else f"{INVENTORY_SCAN_FAILURE_OPERATION_PREFIX}{source_operation_id}"
    )
    return EvidenceOrder(
        token,
        UNKNOWN_RANK,
        tagged_operation_id,
    )
