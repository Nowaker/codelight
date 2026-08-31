from __future__ import annotations

import os
from dataclasses import dataclass

from codelight_core.evidence_order import EvidenceOrder


@dataclass(frozen=True, slots=True)
class PendingTaint:
    agent_prefix: str
    marker_prefix: str
    order: EvidenceOrder
    path: str


class InvalidPendingTaintError(ValueError):
    pass


def looks_like_pending_taint(name: str) -> bool:
    return name.startswith(".") and ".taint." in name and name.endswith(".tmp")


def parse_pending_taint(path: str) -> PendingTaint:
    name = os.path.basename(path)
    if not looks_like_pending_taint(name):
        raise InvalidPendingTaintError
    marker_block, separator, nonce = name[1:-4].partition(".taint.")
    if not separator or not nonce:
        raise InvalidPendingTaintError
    agent_prefix, separator, marker_stem = marker_block.partition(".")
    if not separator:
        raise InvalidPendingTaintError
    parts = marker_stem.split("-", 3)
    if len(parts) != 4:
        raise InvalidPendingTaintError
    marker_prefix, token_text, rank_text, operation_id = parts
    if (
        len(agent_prefix) != 64
        or len(marker_prefix) != 64
        or not token_text.isdigit()
        or len(token_text) != 20
        or not rank_text.isdigit()
        or not operation_id
    ):
        raise InvalidPendingTaintError
    try:
        _ = bytes.fromhex(agent_prefix)
        _ = bytes.fromhex(marker_prefix)
        token = int(token_text)
        rank = int(rank_text)
    except ValueError as error:
        raise InvalidPendingTaintError from error
    if rank not in (0, 1, 2):
        raise InvalidPendingTaintError
    return PendingTaint(
        agent_prefix,
        marker_prefix,
        EvidenceOrder(token, rank, operation_id),
        path,
    )
