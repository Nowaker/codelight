from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_taint_io import TaintOperation


SqlValue = str | int | float | bytes | None


class InvalidEvidenceOrderError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DurableEvidence:
    agent_id: str
    pid: int | None
    started_at: str | None
    executable: str | None
    order: EvidenceOrder


@dataclass(frozen=True, slots=True)
class TaintInvalidations:
    agents: dict[str, EvidenceOrder]
    scopes: dict[tuple[str, int, str, str], EvidenceOrder]


def row_order(row: tuple[SqlValue, ...], offset: int) -> EvidenceOrder:
    token = row[offset]
    rank = row[offset + 1]
    operation_id = row[offset + 2]
    if (
        not isinstance(token, int)
        or isinstance(token, bool)
        or not isinstance(rank, int)
        or isinstance(rank, bool)
        or rank not in (0, 1, 2)
        or not isinstance(operation_id, str)
    ):
        raise InvalidEvidenceOrderError
    return EvidenceOrder(token, rank, operation_id)


def collect_taint_invalidations(
    attempts: Sequence[TaintOperation],
) -> TaintInvalidations:
    zero_order = EvidenceOrder(0, 0, "")
    agents: dict[str, EvidenceOrder] = {}
    scopes: dict[tuple[str, int, str, str], EvidenceOrder] = {}
    for attempt in attempts:
        if attempt.identity is None or attempt.scope_id is None:
            agents[attempt.agent_id] = max(
                agents.get(attempt.agent_id, zero_order),
                attempt.order,
            )
            continue
        key = (
            attempt.agent_id,
            attempt.identity.pid,
            attempt.identity.started_at,
            attempt.scope_id,
        )
        scopes[key] = max(scopes.get(key, zero_order), attempt.order)
    return TaintInvalidations(agents, scopes)


def durable_attempt_evidence(
    attempts: Sequence[TaintOperation],
) -> tuple[DurableEvidence, ...]:
    return tuple(
        DurableEvidence(
            attempt.agent_id,
            attempt.identity.pid if attempt.identity is not None else None,
            attempt.identity.started_at if attempt.identity is not None else None,
            attempt.identity.executable if attempt.identity is not None else None,
            attempt.order,
        )
        for attempt in attempts
    )


def durable_database_evidence(
    agent_invalidations: Mapping[str, EvidenceOrder],
    scope_invalidations: Mapping[tuple[str, int, str, str], EvidenceOrder],
    provider_rows: Sequence[tuple[SqlValue, ...]],
) -> tuple[DurableEvidence, ...]:
    return (
        *(
            DurableEvidence(agent_id, None, None, None, order)
            for agent_id, order in agent_invalidations.items()
        ),
        *(
            DurableEvidence(key[0], key[1], key[2], None, order)
            for key, order in scope_invalidations.items()
        ),
        *(
            DurableEvidence(
                str(row[0]),
                int(row[1]),
                str(row[3]),
                str(row[4]),
                row_order(row, 7),
            )
            for row in provider_rows
        ),
    )


def stale_inventory_agents(
    inventory_order: EvidenceOrder | None,
    live_by_agent: Mapping[str, frozenset[ProcessIdentity]],
    evidence: Sequence[DurableEvidence],
) -> frozenset[str]:
    if inventory_order is None:
        return frozenset()
    live_generations = {
        (agent_id, identity.pid, identity.started_at, identity.executable)
        for agent_id, identities in live_by_agent.items()
        for identity in identities
    }
    return frozenset(
        item.agent_id
        for item in evidence
        if item.order.token >= inventory_order.token
        and (
            item.pid is None
            or item.started_at is None
            or item.executable is None
            or (item.agent_id, item.pid, item.started_at, item.executable)
            not in live_generations
        )
    )
