from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypedDict, assert_never


AuthorityState = Literal["active", "idle", "unknown"]
SessionState = Literal["working", "waiting", "idle", "ended", "unknown"]


class ProviderAuthority(TypedDict):
    state: AuthorityState
    activeSessions: int


class PowerAuthoritySnapshot(TypedDict):
    state: AuthorityState
    reason: str
    providers: dict[str, ProviderAuthority]


@dataclass(frozen=True, slots=True)
class AuthoritySession:
    session_id: str
    agent_id: str
    state: SessionState
    observed_at: float | None = None
    authority_scope: str = ""
    order_token: int | None = None
    authority_rank: int | None = None
    operation_id: str | None = None


def parse_session_state(value: str) -> SessionState:
    match value:
        case "working" | "waiting" | "idle" | "ended" | "unknown":
            return value
        case _:
            return "unknown"


class PowerAuthority:
    """Track which empty session sets are proven idle versus merely missing."""

    def __init__(self) -> None:
        self._enabled_agents: set[str] = set()
        self._observed_scopes: set[tuple[str, str]] = set()
        self._uncertain_scopes: set[tuple[str, str]] = set()
        self._uncertain_sessions: dict[str, tuple[str, str]] = {}
        self._process_states: dict[str, bool | None] = {}
        self._absent_agents: set[str] = set()
        self._process_uncertain_agents: set[str] = set()
        self._awaiting_evidence_agents: set[str] = set()
        self._exact_inventory_agents: set[str] = set()

    def set_enabled_agents(self, agent_ids: set[str]) -> None:
        self._enabled_agents = set(agent_ids)

    def _record_provider_evidence(self, agent_id: str, authority_scope: str) -> None:
        self._observed_scopes.add((agent_id, authority_scope))
        self._process_states[agent_id] = True
        self._absent_agents.discard(agent_id)
        self._awaiting_evidence_agents.discard(agent_id)

    def record(
        self,
        session_id: str,
        state: str,
        agent_id: str,
        complete_provider_evidence: bool = True,
        authority_scope: str = "",
    ) -> None:
        scope = (agent_id, authority_scope)
        match state:
            case "working" | "waiting":
                self._record_provider_evidence(agent_id, authority_scope)
                self._uncertain_sessions.pop(session_id, None)
            case "idle" | "ended":
                if complete_provider_evidence:
                    self._record_provider_evidence(agent_id, authority_scope)
                self._uncertain_sessions.pop(session_id, None)
            case "unknown":
                self._record_provider_evidence(agent_id, authority_scope)
                self._uncertain_sessions[session_id] = scope
            case _:
                self._record_provider_evidence(agent_id, authority_scope)
                self._uncertain_sessions[session_id] = scope
        if complete_provider_evidence:
            self._uncertain_scopes.discard(scope)
        else:
            self._uncertain_scopes.add(scope)

    def record_snapshot(
        self,
        agent_id: str,
        complete: bool,
        authority_scope: str = "",
    ) -> None:
        scope = (agent_id, authority_scope)
        self._record_provider_evidence(agent_id, authority_scope)
        self._uncertain_sessions = {
            session_id: owner
            for session_id, owner in self._uncertain_sessions.items()
            if owner != scope
        }
        if complete:
            self._uncertain_scopes.discard(scope)
        else:
            self._uncertain_scopes.add(scope)

    def forget_scope(self, agent_id: str, authority_scope: str) -> None:
        scope = (agent_id, authority_scope)
        self._observed_scopes.discard(scope)
        self._uncertain_scopes.discard(scope)
        self._uncertain_sessions = {
            session_id: owner
            for session_id, owner in self._uncertain_sessions.items()
            if owner != scope
        }

    def mark_stale(
        self,
        session_id: str,
        agent_id: str,
        authority_scope: str = "",
    ) -> None:
        scope = (agent_id, authority_scope)
        self._observed_scopes.add(scope)
        self._uncertain_sessions[session_id] = scope

    def uncertain_agents(self) -> frozenset[str]:
        return frozenset(
            agent_id
            for agent_id, _scope in (
                self._uncertain_scopes | set(self._uncertain_sessions.values())
            )
        )

    def process_probe_agents(self) -> frozenset[str]:
        return frozenset(
            (self._enabled_agents | set(self.uncertain_agents()))
            - self._exact_inventory_agents
        )

    def record_exact_process_state(
        self,
        agent_id: str,
        alive: bool | None,
    ) -> None:
        self._exact_inventory_agents.add(agent_id)
        self.record_process_state(agent_id, alive)

    def record_process_state(self, agent_id: str, alive: bool | None) -> None:
        previous = self._process_states.get(agent_id)
        self._process_states[agent_id] = alive
        if alive is None:
            self._absent_agents.discard(agent_id)
            self._process_uncertain_agents.add(agent_id)
            return

        self._process_uncertain_agents.discard(agent_id)
        if alive is False:
            self._absent_agents.add(agent_id)
            self._awaiting_evidence_agents.discard(agent_id)
            self._uncertain_sessions = {
                session_id: owner
                for session_id, owner in self._uncertain_sessions.items()
                if owner[0] != agent_id
            }
            self._uncertain_scopes = {
                scope for scope in self._uncertain_scopes if scope[0] != agent_id
            }
            return

        self._absent_agents.discard(agent_id)
        if previous is not True:
            self._awaiting_evidence_agents.add(agent_id)

    def snapshot(
        self,
        sessions: tuple[AuthoritySession, ...],
    ) -> PowerAuthoritySnapshot:
        active_by_agent: dict[str, int] = {}
        for session in sessions:
            match session.state:
                case "working" | "waiting":
                    active_by_agent[session.agent_id] = (
                        active_by_agent.get(session.agent_id, 0) + 1
                    )
                case "idle" | "ended":
                    continue
                case "unknown":
                    self._uncertain_sessions[session.session_id] = (
                        session.agent_id,
                        session.authority_scope,
                    )
                case unreachable:
                    assert_never(unreachable)

        observed_agents = {agent_id for agent_id, _scope in self._observed_scopes}
        uncertain_agents = set(self.uncertain_agents())
        missing_agents = (
            self._enabled_agents
            - observed_agents
            - self._absent_agents
        )
        unknown_agents = (
            uncertain_agents
            | missing_agents
            | self._process_uncertain_agents
            | self._awaiting_evidence_agents
        )
        agents = self._enabled_agents | observed_agents | set(active_by_agent)
        providers: dict[str, ProviderAuthority] = {}
        for agent_id in sorted(agents):
            active_sessions = active_by_agent.get(agent_id, 0)
            if active_sessions > 0:
                provider_state: AuthorityState = "active"
            elif agent_id in unknown_agents:
                provider_state = "unknown"
            else:
                provider_state = "idle"
            providers[agent_id] = {
                "state": provider_state,
                "activeSessions": active_sessions,
            }

        if active_by_agent:
            return {
                "state": "active",
                "reason": "live-session",
                "providers": providers,
            }
        if self._uncertain_sessions or self._uncertain_scopes:
            return {
                "state": "unknown",
                "reason": "stale-session-evidence",
                "providers": providers,
            }
        if self._process_uncertain_agents:
            return {
                "state": "unknown",
                "reason": "process-state-unavailable",
                "providers": providers,
            }
        if self._awaiting_evidence_agents:
            return {
                "state": "unknown",
                "reason": "provider-started-without-evidence",
                "providers": providers,
            }
        if missing_agents:
            return {
                "state": "unknown",
                "reason": "missing-provider-evidence",
                "providers": providers,
            }
        if agents:
            return {
                "state": "idle",
                "reason": "all-sessions-complete",
                "providers": providers,
            }
        return {
            "state": "unknown",
            "reason": "no-session-evidence",
            "providers": {},
        }
