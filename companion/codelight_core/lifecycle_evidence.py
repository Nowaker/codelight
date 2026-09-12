from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from codelight_core.boot_epoch import BootIdentityUnavailable, BootPersistence

from codelight_core.evidence_order import (
    UNKNOWN_RANK,
    EvidenceOrder,
    authority_rank_for_snapshot,
    authority_rank_for_state,
    evidence_order,
    inventory_scan_failure_order,
)
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_invalidation import (
    LifecycleInvalidations,
    ScopeWrite,
)
from codelight_core.lifecycle_evidence_schema import connect_evidence
from codelight_core.lifecycle_evidence_taint import GenerationTaintStore
from codelight_core.lifecycle_evidence_snapshot_write import write_snapshot
from codelight_core.lifecycle_evidence_write import write_event
from codelight_core.power_authority import AuthoritySession


_SESSION_STATES = frozenset({"working", "waiting", "unknown", "idle", "ended"})
_NO_EXPIRY = 9_223_372_036_854_775_807


@dataclass(frozen=True, slots=True)
class StoredSessionEvidence:
    session_id: str
    state: str
    observed_at: float
    order_token: int
    hook_event: str
    authority_rank: int = 0
    operation_id: str = ""

    @property
    def order(self) -> EvidenceOrder:
        return EvidenceOrder(
            self.order_token,
            self.authority_rank,
            self.operation_id,
        )


@dataclass(frozen=True, slots=True)
class StoredProviderEvidence:
    agent_id: str
    identity: ProcessIdentity
    scope_id: str
    observed_at: float
    order_token: int
    lease_deadline_ns: int
    sessions: tuple[StoredSessionEvidence, ...]
    complete: bool
    authority_rank: int = 0
    operation_id: str = ""

    @property
    def order(self) -> EvidenceOrder:
        return EvidenceOrder(
            self.order_token,
            self.authority_rank,
            self.operation_id,
        )


@dataclass(frozen=True, slots=True)
class LifecycleReplay:
    providers: tuple[StoredProviderEvidence, ...]
    stale_inventory_agents: frozenset[str]


class LifecycleEvidenceStore:
    def __init__(self, path: str) -> None:
        self._boot = BootPersistence(path)
        self._path = self._boot.path or f"{path}.unavailable"
        self._taints = GenerationTaintStore(f"{self._path}.taints")
        self._invalidations = LifecycleInvalidations(
            lambda: self._connect(),
            self._taints,
        )

    def _connect(self) -> sqlite3.Connection:
        return connect_evidence(self._boot.verified_path())

    @property
    def boot_id(self) -> str | None:
        return self._boot.epoch

    @staticmethod
    def _order_token(observed_at: float, order_token: int | None) -> int:
        if isinstance(order_token, int) and not isinstance(order_token, bool):
            return order_token
        return int(observed_at * 1_000_000_000)

    def invalidate_agent(
        self,
        agent_id: str,
        order_token: int,
        operation_id: str | None = None,
    ) -> None:
        order = evidence_order(order_token, UNKNOWN_RANK, operation_id)
        self._boot.verified_path()
        self._invalidations.invalidate_agent(agent_id, order)

    def invalidate_inventory_scan_failure(
        self,
        agent_id: str,
        order_token: int,
        operation_id: str | None = None,
    ) -> None:
        order = inventory_scan_failure_order(order_token, operation_id)
        self._boot.verified_path()
        self._invalidations.invalidate_agent(agent_id, order)

    def clear_agent_invalidation(
        self,
        agent_id: str,
        order_token: int,
        operation_id: str | None = None,
    ) -> None:
        order = evidence_order(order_token, UNKNOWN_RANK, operation_id)
        self._boot.verified_path()
        self._invalidations.clear_agent(agent_id, order)

    def record(
        self,
        *,
        agent_id: str,
        identity: ProcessIdentity,
        session_id: str,
        state: str,
        observed_at: float,
        hook_event: str,
        complete: bool = True,
        scope_id: str = "",
        order_token: int | None = None,
        authority_rank: int | None = None,
        operation_id: str | None = None,
        lease_deadline_ns: int | None = None,
    ) -> None:
        if state not in _SESSION_STATES:
            state = "unknown"
        self._boot.verified_path()
        if not identity.boot_id or identity.boot_id != self.boot_id:
            raise BootIdentityUnavailable('provider origin boot mismatch')
        token = self._order_token(observed_at, order_token)
        rank = (
            authority_rank
            if authority_rank is not None
            else authority_rank_for_state(state, complete)
        )
        order = evidence_order(token, rank, operation_id)
        deadline = lease_deadline_ns if lease_deadline_ns is not None else _NO_EXPIRY
        sidecar = self._invalidations.begin_scope_write(
            ScopeWrite(agent_id, identity, scope_id, order)
        )
        connection = self._connect()
        try:
            with connection:
                write_event(
                    connection,
                    agent_id=agent_id,
                    identity=identity,
                    scope_id=scope_id,
                    session_id=session_id,
                    state=state,
                    observed_at=observed_at,
                    order=order,
                    lease_deadline_ns=deadline,
                    hook_event=hook_event,
                    complete=complete,
                    sidecar=sidecar is not None,
                )
        finally:
            connection.close()
        if sidecar is not None:
            self._taints.clear_success(sidecar)

    def record_snapshot(
        self,
        *,
        agent_id: str,
        identity: ProcessIdentity,
        sessions: tuple[AuthoritySession, ...],
        complete: bool,
        observed_at: float,
        scope_id: str = "",
        order_token: int | None = None,
        authority_rank: int | None = None,
        operation_id: str | None = None,
        lease_deadline_ns: int | None = None,
    ) -> None:
        token = self._order_token(observed_at, order_token)
        self._boot.verified_path()
        if not identity.boot_id or identity.boot_id != self.boot_id:
            raise BootIdentityUnavailable('provider origin boot mismatch')
        rank = (
            authority_rank
            if authority_rank is not None
            else authority_rank_for_snapshot(
                tuple(session.state for session in sessions),
                complete,
            )
        )
        order = evidence_order(token, rank, operation_id)
        deadline = lease_deadline_ns if lease_deadline_ns is not None else _NO_EXPIRY
        sidecar = self._invalidations.begin_scope_write(
            ScopeWrite(agent_id, identity, scope_id, order)
        )
        connection = self._connect()
        try:
            with connection:
                write_snapshot(
                    connection,
                    agent_id=agent_id,
                    identity=identity,
                    scope_id=scope_id,
                    sessions=sessions,
                    complete=complete,
                    observed_at=observed_at,
                    order=order,
                    lease_deadline_ns=deadline,
                    sidecar=sidecar is not None,
                )
        finally:
            connection.close()
        if complete:
            self._taints.clear_scope_through(
                agent_id,
                identity,
                scope_id,
                order,
            )
        elif sidecar is not None:
            self._taints.clear_success(sidecar)

    def replay(
        self,
        live_by_agent: dict[str, frozenset[ProcessIdentity]],
        *,
        now_order_token: int | None = None,
    ) -> tuple[StoredProviderEvidence, ...]:
        from codelight_core.lifecycle_evidence_replay import replay_evidence

        return replay_evidence(
            self._connect,
            self._taints,
            live_by_agent,
            now_order_token if now_order_token is not None else time.monotonic_ns(),
            None,
        ).providers

    def replay_inventory(
        self,
        live_by_agent: dict[str, frozenset[ProcessIdentity]],
        inventory_order: EvidenceOrder,
        *,
        now_order_token: int | None = None,
    ) -> LifecycleReplay:
        from codelight_core.lifecycle_evidence_replay import replay_evidence

        for agent_id in live_by_agent:
            try:
                self._invalidations.clear_inventory_scan_failures_before(
                    agent_id,
                    inventory_order,
                )
            except (OSError, sqlite3.Error):
                pass
        return replay_evidence(
            self._connect,
            self._taints,
            live_by_agent,
            now_order_token if now_order_token is not None else time.monotonic_ns(),
            inventory_order,
        )
