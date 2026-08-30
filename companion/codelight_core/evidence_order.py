from __future__ import annotations

import uuid
from dataclasses import dataclass


IDLE_RANK = 0
UNKNOWN_RANK = 1
ACTIVE_RANK = 2


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
