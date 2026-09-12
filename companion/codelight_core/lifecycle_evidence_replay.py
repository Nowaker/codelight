from __future__ import annotations

import sqlite3
from collections.abc import Callable

from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_inventory import (
    SqlValue,
    collect_taint_invalidations,
    durable_attempt_evidence,
    durable_database_evidence,
    row_order,
    stale_inventory_agents,
)
from codelight_core.lifecycle_evidence_taint import GenerationTaintStore
from codelight_core.lifecycle_recovery import recover_agent_floors


_SESSION_STATES = frozenset({"working", "waiting", "unknown", "idle", "ended"})
_ZERO_ORDER = EvidenceOrder(0, 0, "")


def _live_key(agent_id: str, identity: ProcessIdentity) -> tuple[str, int, str, str]:
    return agent_id, identity.pid, identity.started_at, identity.executable


def _scope_key(
    agent_id: str,
    identity: ProcessIdentity,
    scope_id: str,
) -> tuple[str, int, str, str]:
    return agent_id, identity.pid, identity.started_at, scope_id


def _unknown_provider(
    agent_id: str,
    identity: ProcessIdentity,
    scope_id: str = "",
    order: EvidenceOrder = _ZERO_ORDER,
):
    from codelight_core.lifecycle_evidence import StoredProviderEvidence

    return StoredProviderEvidence(
        agent_id=agent_id,
        identity=identity,
        scope_id=scope_id,
        observed_at=0.0,
        order_token=order.token,
        authority_rank=order.authority_rank,
        operation_id=order.operation_id,
        lease_deadline_ns=0,
        sessions=(),
        complete=False,
    )


def _unknown_for_live(live_by_agent: dict[str, frozenset[ProcessIdentity]]):
    return tuple(
        _unknown_provider(agent_id, identity)
        for agent_id, identities in sorted(live_by_agent.items())
        for identity in sorted(identities, key=lambda item: item.pid)
    )


def _fully_recovered_agents(
    invalidations: dict[str, EvidenceOrder],
    rows: list[tuple[SqlValue, ...]],
    live: dict[tuple[str, int, str, str], ProcessIdentity],
    now_order_token: int,
) -> set[str]:
    recovered_generations = {
        (str(row[0]), int(row[1]), str(row[3]), str(row[4]))
        for row in rows
        if str(row[0]) in invalidations
        and row[11] == 1
        and int(row[10]) >= now_order_token
        and row_order(row, 7) == row_order(row, 12)
        and row_order(row, 12) > invalidations[str(row[0])]
    }
    return {
        agent_id
        for agent_id in invalidations
        if any(key[0] == agent_id for key in live)
        and all(
            key in recovered_generations
            for key in live
            if key[0] == agent_id
        )
    }


def replay_evidence(
    connect: Callable[[], sqlite3.Connection],
    taints: GenerationTaintStore,
    live_by_agent: dict[str, frozenset[ProcessIdentity]],
    now_order_token: int,
    inventory_order: EvidenceOrder | None,
):
    from codelight_core.lifecycle_evidence import (
        LifecycleReplay,
        StoredProviderEvidence,
        StoredSessionEvidence,
    )

    live = {
        _live_key(agent_id, identity): identity
        for agent_id, identities in live_by_agent.items()
        for identity in identities
    }
    unavailable = frozenset(live_by_agent) if inventory_order is not None else frozenset()
    try:
        attempts, malformed_taint = taints.attempts()
    except OSError:
        return LifecycleReplay(_unknown_for_live(live_by_agent), unavailable)
    if malformed_taint:
        return LifecycleReplay(_unknown_for_live(live_by_agent), unavailable)
    durable_evidence = durable_attempt_evidence(attempts)
    taint_invalidations = collect_taint_invalidations(attempts)
    try:
        connection = connect()
    except (OSError, sqlite3.Error):
        return LifecycleReplay(_unknown_for_live(live_by_agent), unavailable)
    try:
        connection.execute("BEGIN")
        agent_invalidations: dict[str, EvidenceOrder] = {}
        for row in connection.execute(
            """
            SELECT agent_id, order_token, authority_rank, operation_id
            FROM agent_invalidations
            """
        ):
            agent_id = str(row[0])
            agent_invalidations[agent_id] = max(
                agent_invalidations.get(agent_id, _ZERO_ORDER),
                row_order(tuple(row), 1),
            )
        scope_invalidations: dict[
            tuple[str, int, str, str], EvidenceOrder
        ] = {}
        for row in connection.execute(
            """
            SELECT agent_id, pid, started_at, scope_id,
                   order_token, authority_rank, operation_id
            FROM scope_invalidations
            """
        ):
            key = (str(row[0]), int(row[1]), str(row[2]), str(row[3]))
            scope_invalidations[key] = max(
                scope_invalidations.get(key, _ZERO_ORDER),
                row_order(tuple(row), 4),
            )
        for key, order in taint_invalidations.scopes.items():
            scope_invalidations[key] = max(
                scope_invalidations.get(key, _ZERO_ORDER),
                order,
            )
        for agent_id, order in taint_invalidations.agents.items():
            agent_invalidations[agent_id] = max(
                agent_invalidations.get(agent_id, _ZERO_ORDER),
                order,
            )
        rows = connection.execute(
            """
            SELECT agent_id, pid, ppid, started_at, executable, scope_id,
                   observed_at, order_token, authority_rank, operation_id,
                   lease_deadline_ns, complete,
                   snapshot_order_token, snapshot_authority_rank,
                   snapshot_operation_id
            FROM provider_evidence
            ORDER BY agent_id, pid, started_at, scope_id
            """
        ).fetchall()
        floors = recover_agent_floors(
            connection, rows, live=live, invalidations=agent_invalidations,
            inventory_order=inventory_order, now_order_token=now_order_token,
        )
        agent_invalidations = {
            agent_id: order for agent_id, order in agent_invalidations.items()
            if order.token >= floors.get(agent_id, 0)
        }
        durable_evidence = tuple(
            item for item in durable_evidence
            if item.pid is not None or item.order.token >= floors.get(item.agent_id, 0)
        )
        for agent_id in _fully_recovered_agents(
            agent_invalidations,
            rows,
            live,
            now_order_token,
        ):
            del agent_invalidations[agent_id]
        stale_agents = stale_inventory_agents(
            inventory_order,
            live_by_agent,
            (
                *durable_evidence,
                *durable_database_evidence(
                    agent_invalidations,
                    scope_invalidations,
                    tuple(tuple(row) for row in rows),
                ),
            ),
        )
        providers = []
        matched_live: set[tuple[str, int, str, str]] = set()
        matched_scopes: set[tuple[str, int, str, str]] = set()
        for row in rows:
            row = tuple(row)
            agent_id = str(row[0])
            live_key = (agent_id, int(row[1]), str(row[3]), str(row[4]))
            identity = live.get(live_key)
            if identity is None:
                continue
            matched_live.add(live_key)
            scope_id = str(row[5])
            invalidation_key = _scope_key(agent_id, identity, scope_id)
            matched_scopes.add(invalidation_key)
            provider_order = row_order(row, 7)
            invalidation_order = max(
                scope_invalidations.get(invalidation_key, _ZERO_ORDER),
                agent_invalidations.get(agent_id, _ZERO_ORDER),
            )
            invalid = (
                invalidation_key in scope_invalidations
                or agent_id in agent_invalidations
                or int(row[10]) < now_order_token
            )
            session_rows = () if invalid else connection.execute(
                """
                SELECT session_id, state, observed_at, order_token,
                       authority_rank, operation_id, hook_event
                FROM session_evidence
                WHERE agent_id = ? AND pid = ? AND started_at = ?
                  AND scope_id = ?
                ORDER BY session_id
                """,
                (agent_id, identity.pid, identity.started_at, scope_id),
            ).fetchall()
            valid_sessions = all(
                isinstance(session[0], str)
                and bool(session[0])
                and isinstance(session[1], str)
                and session[1] in _SESSION_STATES
                and isinstance(session[6], str)
                for session in session_rows
            )
            valid_complete = isinstance(row[11], int) and row[11] in (0, 1)
            if not valid_sessions or not valid_complete:
                invalid = True
                session_rows = ()
            sessions = tuple(
                StoredSessionEvidence(
                    session_id=str(session[0]),
                    state=str(session[1]),
                    observed_at=float(session[2]),
                    order_token=row_order(tuple(session), 3).token,
                    authority_rank=row_order(tuple(session), 3).authority_rank,
                    operation_id=row_order(tuple(session), 3).operation_id,
                    hook_event=str(session[6]),
                )
                for session in session_rows
            )
            resulting_order = max(provider_order, invalidation_order)
            providers.append(StoredProviderEvidence(
                agent_id=agent_id,
                identity=identity,
                scope_id=scope_id,
                observed_at=float(row[6]),
                order_token=resulting_order.token,
                authority_rank=resulting_order.authority_rank,
                operation_id=resulting_order.operation_id,
                lease_deadline_ns=int(row[10]),
                sessions=sessions,
                complete=bool(row[11]) and not invalid,
                snapshot_order=(
                    row_order(row, 12)
                    if not invalid and row_order(row, 12) > _ZERO_ORDER else None
                ),
            ))
        for scope_key, invalidation_order in scope_invalidations.items():
            if scope_key in matched_scopes:
                continue
            agent_id, pid, generation, scope_id = scope_key
            identity = next(
                (
                    item
                    for key, item in live.items()
                    if key[0] == agent_id
                    and key[1] == pid
                    and key[2] == generation
                ),
                None,
            )
            if identity is None:
                continue
            matched_live.add(_live_key(agent_id, identity))
            providers.append(
                _unknown_provider(agent_id, identity, scope_id, invalidation_order)
            )
        providers.extend(
            _unknown_provider(
                live_key[0],
                identity,
                order=agent_invalidations.get(live_key[0], _ZERO_ORDER),
            )
            for live_key, identity in live.items()
            if live_key not in matched_live
        )
        connection.execute("COMMIT")
        return LifecycleReplay(tuple(providers), stale_agents)
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return LifecycleReplay(_unknown_for_live(live_by_agent), unavailable)
    finally:
        connection.close()
