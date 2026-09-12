from __future__ import annotations

import math
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Any, Callable

from codelight_core.evidence_order import (
    EvidenceOrder,
    authority_rank_for_snapshot,
    authority_rank_for_state,
    evidence_order,
)
from codelight_core.power_authority import (
    AuthoritySession,
    PowerAuthority,
    PowerAuthoritySnapshot,
    parse_session_state,
)


DEFAULT_USAGE: dict[str, Any] = {
    "session_pct": 0.0,
    "weekly_pct": 0.0,
    "session_reset": "--",
    "weekly_reset": "--",
    "session_reset_at": 0,
    "weekly_reset_at": 0,
}


@dataclass(frozen=True)
class ActiveTranscript:
    session_id: str
    path: str
    agent_id: str = ""


class CodelightState:
    """Thread-safe owner for live session state and per-agent usage caches.

    The daemon still exposes legacy helper functions, but they should take
    snapshots from this object instead of reaching into module globals. That
    keeps broadcaster/rendering code on immutable copies and makes later agent
    backends additive.
    """

    def __init__(
        self,
        *,
        default_agent_id: str,
        agent_registry: dict[str, dict[str, str]],
        idle_window: int,
        idle_window_waiting: int,
        agent_process_alive: Callable[[str], bool | None] = lambda _agent_id: None,
        agent_process_states: Callable[
            [set[str]], dict[str, bool | None]
        ] | None = None,
        activity_resolver: Callable[
            [tuple[AuthoritySession, ...], frozenset[str]], tuple[AuthoritySession, ...]
        ] = lambda sessions, covered_agents: sessions,
    ) -> None:
        self._lock = threading.RLock()
        self._default_agent_id = default_agent_id
        self._agent_registry = agent_registry
        self._idle_window = idle_window
        self._idle_window_waiting = idle_window_waiting
        self._agent_process_alive = agent_process_alive
        self._activity_resolver = activity_resolver
        self._agent_process_states = agent_process_states or (
            lambda agent_ids: {
                agent_id: self._agent_process_alive(agent_id)
                for agent_id in agent_ids
            }
        )
        self._sessions: dict[str, dict[str, Any]] = {}
        self._session_versions: dict[tuple[str, str, str], EvidenceOrder] = {}
        self._provider_versions: dict[tuple[str, str], EvidenceOrder] = {}
        self._complete_snapshot_versions: dict[
            tuple[str, str], EvidenceOrder
        ] = {}
        self._scope_generations: dict[tuple[str, str], str] = {}
        self._scope_lease_deadlines: dict[tuple[str, str], int] = {}
        self._replayed_scopes: set[tuple[str, str]] = set()
        self._live_generations: dict[str, frozenset[str]] = {}
        self._coverage_pending: set[str] = set()
        self._power_authority = PowerAuthority()
        self._usage_caches: dict[str, dict[str, Any]] = {
            self._default_agent_id: dict(DEFAULT_USAGE),
        }
        self._last_transcript: dict[str, str] = {"sid": "", "path": ""}
        # agent_id → {"sid", "path"}: newest transcript seen per agent, so a
        # client can request any conversation-capable agent's latest feed.
        self._transcripts_by_agent: dict[str, dict[str, str]] = {}
        self._last_active_agent: str = default_agent_id
        # Configured agents shown as idle even without a usage meter or an
        # active session, so hook-only agents (no readable quota) stay visible.
        self._enabled_agents: set[str] = set()

    def set_enabled_agents(self, agent_ids) -> None:
        with self._lock:
            self._enabled_agents = {
                self.normalize_agent_id(a) for a in (agent_ids or set())
            }
            self._power_authority.set_enabled_agents(self._enabled_agents)

    def normalize_agent_id(self, agent_id: str | None) -> str:
        aid = str(agent_id or "").strip().lower()
        return aid if aid else self._default_agent_id

    @staticmethod
    def _session_key(authority_scope: str, session_id: str) -> str:
        return session_id if not authority_scope else f"{authority_scope}\x1f{session_id}"

    @staticmethod
    def _event_order(
        observed_at: float,
        order_token: int | None,
        authority_rank: int,
        operation_id: str | None,
    ) -> EvidenceOrder:
        token = (
            order_token
            if isinstance(order_token, int) and not isinstance(order_token, bool)
            else time.monotonic_ns()
        )
        return evidence_order(token, authority_rank, operation_id)

    @property
    def default_agent_id(self) -> str:
        return self._default_agent_id

    def agent_display_name(self, agent_id: str | None) -> str:
        aid = self.normalize_agent_id(agent_id)
        if aid in self._agent_registry:
            return self._agent_registry[aid]["display"]
        return aid.capitalize() if aid else self._agent_registry[self._default_agent_id]["display"]

    def agent_meter_titles(self, agent_id: str | None) -> tuple[str, str]:
        display = self.agent_display_name(agent_id)
        return f"{display} Weekly", f"{display} Session"

    def update_session(
        self,
        session_id: str,
        state: str,
        *,
        transcript: str = "",
        cwd: str = "",
        agent_id: str | None = None,
        observed_at: float | None = None,
        provider_evidence_complete: bool = True,
        order_token: int | None = None,
        authority_rank: int | None = None,
        operation_id: str | None = None,
        authority_scope: str = "",
        authority_generation: str = "",
        lease_deadline_ns: int | None = None,
    ) -> None:
        normalized_agent = self.normalize_agent_id(agent_id)
        event_time = (
            observed_at
            if observed_at is not None and math.isfinite(observed_at)
            else time.time()
        )
        event_order = self._event_order(
            event_time,
            order_token,
            authority_rank
            if authority_rank is not None
            else authority_rank_for_state(state, provider_evidence_complete),
            operation_id,
        )
        scope_key = (normalized_agent, authority_scope)
        internal_session_id = self._session_key(authority_scope, session_id)
        with self._lock:
            complete_snapshot_version = self._complete_snapshot_versions.get(
                scope_key
            )
            if (
                complete_snapshot_version is not None
                and event_order < complete_snapshot_version
            ):
                return
            version_key = (normalized_agent, authority_scope, session_id)
            previous_version = self._session_versions.get(version_key)
            if previous_version is not None and event_order < previous_version:
                return
            self._session_versions[version_key] = event_order
            self._provider_versions[scope_key] = max(
                event_order,
                self._provider_versions.get(scope_key, event_order),
            )
            if authority_generation:
                self._scope_generations[scope_key] = authority_generation
            if lease_deadline_ns is not None:
                self._scope_lease_deadlines[scope_key] = lease_deadline_ns
            self._replayed_scopes.discard(scope_key)
            self._power_authority.record(
                internal_session_id,
                state,
                normalized_agent,
                provider_evidence_complete,
                authority_scope,
            )
            if transcript:
                self._last_transcript = {
                    "sid": session_id,
                    "path": transcript,
                    "agent_id": normalized_agent,
                }
                self._transcripts_by_agent[normalized_agent] = {
                    "sid": session_id,
                    "path": transcript,
                }
            if state in ("ended", "idle", "unknown"):
                self._sessions.pop(internal_session_id, None)
            else:
                info = dict(self._sessions.get(internal_session_id, {}))
                info["session_id"] = session_id
                info["state"] = state
                info["time"] = event_time
                info["order_token"] = event_order.token
                info["authority_rank"] = event_order.authority_rank
                info["operation_id"] = event_order.operation_id
                if transcript:
                    info["transcript"] = transcript
                if cwd:
                    info["cwd"] = cwd
                info["agent_id"] = normalized_agent
                info["authority_scope"] = authority_scope
                info["authority_generation"] = authority_generation
                self._sessions[internal_session_id] = info
            if state in ("working", "waiting"):
                self._last_active_agent = normalized_agent

    def update_provider_snapshot(
        self,
        sessions: tuple[AuthoritySession, ...],
        *,
        agent_id: str,
        complete: bool,
        observed_at: float,
        order_token: int | None = None,
        authority_rank: int | None = None,
        operation_id: str | None = None,
        authority_scope: str = "",
        authority_generation: str = "",
        lease_deadline_ns: int | None = None,
        replayed: bool = False,
        snapshot_order: EvidenceOrder | None = None,
        verified_generation: bool = False,
    ) -> None:
        normalized_agent = self.normalize_agent_id(agent_id)
        event_time = observed_at if math.isfinite(observed_at) else time.time()
        event_order = self._event_order(
            event_time,
            order_token,
            authority_rank
            if authority_rank is not None
            else authority_rank_for_snapshot(
                tuple(session.state for session in sessions),
                complete,
            ),
            operation_id,
        )
        scope_key = (normalized_agent, authority_scope)
        with self._lock:
            previous_provider_version = self._provider_versions.get(
                scope_key
            )
            if (
                previous_provider_version is not None
                and event_order < previous_provider_version
            ):
                return
            self._provider_versions[scope_key] = event_order
            if (complete and not replayed and verified_generation and authority_generation
                    and normalized_agent in self._live_generations):
                self._live_generations[normalized_agent] |= frozenset({authority_generation})
            if complete:
                if not replayed:
                    self._complete_snapshot_versions[scope_key] = event_order
                elif snapshot_order is not None:
                    self._complete_snapshot_versions[scope_key] = snapshot_order
                else:
                    self._complete_snapshot_versions.pop(scope_key, None)
            if authority_generation:
                self._scope_generations[scope_key] = authority_generation
            if lease_deadline_ns is not None:
                self._scope_lease_deadlines[scope_key] = lease_deadline_ns
            if replayed:
                self._replayed_scopes.add(scope_key)
            else:
                self._replayed_scopes.discard(scope_key)
            self._power_authority.record_snapshot(
                normalized_agent,
                complete,
                authority_scope,
            )

            incoming = {
                self._session_key(authority_scope, session.session_id): session
                for session in sessions
            }
            existing = {
                internal_session_id
                for internal_session_id, info in self._sessions.items()
                if self.normalize_agent_id(info.get("agent_id"))
                == normalized_agent
                and str(info.get("authority_scope") or "") == authority_scope
            }
            affected = set(incoming)
            if complete:
                affected.update(existing)

            for internal_session_id in affected:
                session = incoming.get(internal_session_id)
                session_id = (
                    session.session_id
                    if session is not None
                    else str(
                        self._sessions.get(internal_session_id, {}).get(
                            "session_id",
                            internal_session_id,
                        )
                    )
                )
                session_time = (
                    session.observed_at
                    if session is not None
                    and session.observed_at is not None
                    and math.isfinite(session.observed_at)
                    else event_time
                )
                session_order = event_order
                if session is not None and session.order_token is not None:
                    session_order = EvidenceOrder(
                        session.order_token,
                        session.authority_rank
                        if session.authority_rank is not None
                        else authority_rank_for_state(session.state, complete),
                        session.operation_id or event_order.operation_id,
                    )
                version_key = (normalized_agent, authority_scope, session_id)
                previous_session_version = self._session_versions.get(version_key)
                if (
                    previous_session_version is not None
                    and session_order < previous_session_version
                ):
                    continue
                self._session_versions[version_key] = session_order
                if session is None or session.state in (
                    "idle",
                    "ended",
                    "unknown",
                ):
                    self._sessions.pop(internal_session_id, None)
                    continue
                info = dict(self._sessions.get(internal_session_id, {}))
                info["session_id"] = session_id
                info["state"] = session.state
                info["time"] = session_time
                info["order_token"] = session_order.token
                info["authority_rank"] = session_order.authority_rank
                info["operation_id"] = session_order.operation_id
                info["agent_id"] = normalized_agent
                info["authority_scope"] = authority_scope
                info["authority_generation"] = authority_generation
                self._sessions[internal_session_id] = info
                self._last_active_agent = normalized_agent

    def _forget_scope_locked(self, scope_key: tuple[str, str]) -> None:
        normalized_agent, authority_scope = scope_key
        self._power_authority.forget_scope(normalized_agent, authority_scope)
        self._provider_versions.pop(scope_key, None)
        self._complete_snapshot_versions.pop(scope_key, None)
        self._scope_generations.pop(scope_key, None)
        self._scope_lease_deadlines.pop(scope_key, None)
        self._replayed_scopes.discard(scope_key)
        self._sessions = {
            session_key: info
            for session_key, info in self._sessions.items()
            if not (
                self.normalize_agent_id(info.get("agent_id")) == normalized_agent
                and str(info.get("authority_scope") or "") == authority_scope
            )
        }
        self._session_versions = {
            version_key: version
            for version_key, version in self._session_versions.items()
            if version_key[:2] != scope_key
        }

    def record_process_inventory(
        self,
        agent_id: str,
        alive: bool | None,
        inventory_order: EvidenceOrder | None = None,
    ) -> None:
        normalized_agent = self.normalize_agent_id(agent_id)
        with self._lock:
            self._live_generations.pop(normalized_agent, None)
            if inventory_order is not None and any(
                scope_key[0] == normalized_agent and version > inventory_order
                for scope_key, version in self._provider_versions.items()
            ):
                return
            self._power_authority.record_exact_process_state(
                normalized_agent,
                alive,
            )
            if alive is False:
                self._forget_scope_locked(
                    (normalized_agent, f"unresolved:{normalized_agent}")
                )

    def _settled_unresolved_scope_locked(
        self,
        normalized_agent: str,
        live_generations: frozenset[str],
        inventory_order: EvidenceOrder | None,
    ) -> tuple[str, str] | None:
        scope_key = (normalized_agent, f"unresolved:{normalized_agent}")
        claim = self._provider_versions.get(scope_key)
        if claim is None or inventory_order is None or claim > inventory_order:
            return None
        settled_generations = set()
        for candidate, generation in self._scope_generations.items():
            if candidate[0] != normalized_agent:
                continue
            complete = self._complete_snapshot_versions.get(candidate)
            if complete is not None and claim < complete <= inventory_order:
                settled_generations.add(generation)
        if not live_generations <= settled_generations:
            return None
        return scope_key

    def reconcile_replayed_authority(
        self,
        agent_id: str,
        live_generations: frozenset[str],
        replayed_scopes: frozenset[str],
        inventory_order: EvidenceOrder | None = None,
    ) -> None:
        normalized_agent = self.normalize_agent_id(agent_id)
        with self._lock:
            if inventory_order is not None:
                self._live_generations[normalized_agent] = live_generations
            dead_scopes = {
                scope_key
                for scope_key, generation in self._scope_generations.items()
                if scope_key[0] == normalized_agent
                and generation not in live_generations
                and (
                    inventory_order is None
                    or self._provider_versions.get(scope_key) is None
                    or self._provider_versions[scope_key] <= inventory_order
                )
            }
            stale_replayed = {
                scope_key
                for scope_key in self._replayed_scopes
                if scope_key[0] == normalized_agent
                and scope_key[1] not in replayed_scopes
                and (
                    inventory_order is None
                    or self._provider_versions.get(scope_key) is None
                    or self._provider_versions[scope_key] <= inventory_order
                )
            }
            settled_unresolved = self._settled_unresolved_scope_locked(
                normalized_agent,
                live_generations,
                inventory_order,
            )
            retired = dead_scopes | stale_replayed
            if settled_unresolved is not None:
                retired = retired | {settled_unresolved}
            for scope_key in retired:
                self._forget_scope_locked(scope_key)

    @contextmanager
    def authority_restore(self, agent_ids: set[str]) -> Iterator[None]:
        with self._lock:
            self.begin_authority_restore(agent_ids)
            committed = False
            try:
                yield
                committed = True
            finally:
                if not committed:
                    for agent_id in agent_ids:
                        self.record_process_inventory(agent_id, None)
                self.finish_authority_restore(agent_ids)

    def begin_authority_restore(self, agent_ids: set[str]) -> None:
        with self._lock:
            self._coverage_pending.update(agent_ids)
            for agent_id in agent_ids:
                self._live_generations.pop(agent_id, None)

    def finish_authority_restore(self, agent_ids: set[str]) -> None:
        with self._lock:
            self._coverage_pending.difference_update(agent_ids)

    def _covered_agents_locked(self) -> frozenset[str]:
        uncertain = self._power_authority.coverage_uncertain_agents()
        covered: set[str] = set()
        now = time.monotonic_ns()
        for agent_id, live in self._live_generations.items():
            if not live or agent_id in uncertain or agent_id in self._coverage_pending:
                continue
            scopes = {key for key in self._provider_versions if key[0] == agent_id}
            if scopes and all(
                self._provider_versions[key] == self._complete_snapshot_versions.get(key)
                and self._scope_generations.get(key, "") in live
                and bool(self._scope_generations.get(key))
                and self._scope_lease_deadlines.get(key, 0) > now
                for key in scopes
            ) and live == {self._scope_generations[key] for key in scopes}:
                covered.add(agent_id)
        return frozenset(covered)

    def _expire_authority_scopes_locked(self, now_order_token: int) -> None:
        expired = {
            scope_key
            for scope_key, deadline in self._scope_lease_deadlines.items()
            if deadline < now_order_token
        }
        for normalized_agent, authority_scope in expired:
            self._scope_lease_deadlines.pop(
                (normalized_agent, authority_scope),
                None,
            )
            self._power_authority.record_snapshot(
                normalized_agent,
                False,
                authority_scope,
            )
            self._sessions = {
                session_key: info
                for session_key, info in self._sessions.items()
                if not (
                    self.normalize_agent_id(info.get("agent_id"))
                    == normalized_agent
                    and str(info.get("authority_scope") or "")
                    == authority_scope
                )
            }

    def active_transcript(self) -> ActiveTranscript:
        with self._lock:
            best: tuple[str, int, str, str] | None = None
            for session_key, info in self._sessions.items():
                transcript = str(info.get("transcript") or "")
                order_token = int(info.get("order_token") or 0)
                if transcript and (best is None or order_token > best[1]):
                    best = (
                            str(info.get("session_id") or session_key),
                            order_token,
                            transcript,
                            self.normalize_agent_id(info.get("agent_id")))
            if best:
                # Agent travels with the transcript so the conversation label
                # can never diverge from the content being shown.
                return ActiveTranscript(best[0], best[2], best[3])
            path = self._last_transcript.get("path", "")
            if path:
                return ActiveTranscript(
                    self._last_transcript.get("sid", ""),
                    path,
                    self.normalize_agent_id(
                        self._last_transcript.get("agent_id")),
                )
        return ActiveTranscript("", "")

    def transcript_for_agent(self, agent_id: str) -> ActiveTranscript:
        """Latest known transcript for a specific agent: an active session's
        first, else the newest transcript that agent ever reported this run."""
        aid = self.normalize_agent_id(agent_id)
        with self._lock:
            best: tuple[str, int, str] | None = None
            for session_key, info in self._sessions.items():
                if self.normalize_agent_id(info.get("agent_id")) != aid:
                    continue
                transcript = str(info.get("transcript") or "")
                order_token = int(info.get("order_token") or 0)
                if transcript and (best is None or order_token > best[1]):
                    best = (
                        str(info.get("session_id") or session_key),
                        order_token,
                        transcript,
                    )
            if best:
                return ActiveTranscript(best[0], best[2], aid)
            rec = self._transcripts_by_agent.get(aid)
            if rec and rec.get("path"):
                return ActiveTranscript(rec.get("sid", ""), rec["path"], aid)
        return ActiveTranscript("", "", aid)

    @staticmethod
    def _status_rank(status: str) -> int:
        return {"idle": 0, "waiting": 1, "working": 2}.get(status, 0)

    def overall_status(self, pending_session_ids: set[str] | None = None) -> tuple[int, str, dict[str, str], str]:
        pending_session_ids = pending_session_ids or set()
        now_order_token = time.monotonic_ns()
        active = 0
        overall = "idle"
        per_agent: dict[str, str] = {}
        with self._lock:
            self._expire_authority_scopes_locked(now_order_token)
            last_agent = self.normalize_agent_id(self._last_active_agent)
            stale = [
                session_key for session_key, info in self._sessions.items()
                if str(info.get("session_id") or session_key)
                not in pending_session_ids
                and now_order_token - int(info.get("order_token") or 0) > (
                    self._idle_window_waiting
                    if info.get("state") == "waiting"
                    else self._idle_window
                ) * 1_000_000_000
            ]
            for session_key in stale:
                agent_id = self.normalize_agent_id(
                    self._sessions[session_key].get("agent_id")
                )
                authority_scope = str(
                    self._sessions[session_key].get("authority_scope") or ""
                )
                self._power_authority.mark_stale(
                    session_key,
                    agent_id,
                    authority_scope,
                )
                del self._sessions[session_key]
            for info in self._sessions.values():
                active += 1
                state = str(info.get("state") or "idle")
                agent_id = self.normalize_agent_id(info.get("agent_id"))
                prev = per_agent.get(agent_id, "idle")
                if self._status_rank(state) > self._status_rank(prev):
                    per_agent[agent_id] = state
                if state == "working":
                    overall = "working"
                elif state == "waiting" and overall != "working":
                    overall = "waiting"
            # Every configured agent stays visible (idle) even with no active
            # session — agents without a usage meter would otherwise vanish.
            for agent_id in self._enabled_agents:
                per_agent.setdefault(agent_id, "idle")
            if not per_agent:
                per_agent[last_agent] = "idle"
            return active, overall, per_agent, last_agent

    def power_authority_snapshot(
        self,
        pending_session_ids: set[str] | None = None,
    ) -> PowerAuthoritySnapshot:
        self.overall_status(pending_session_ids)
        with self._lock:
            probe_agents = set(self._power_authority.process_probe_agents())
            process_states = self._agent_process_states(probe_agents)
            for agent_id in probe_agents:
                self._power_authority.record_process_state(
                    agent_id,
                    process_states.get(agent_id),
                )
            sessions = tuple(
                AuthoritySession(
                    session_id=str(info.get("session_id") or session_key),
                    agent_id=self.normalize_agent_id(info.get("agent_id")),
                    state=parse_session_state(str(info.get("state") or "unknown")),
                    authority_scope=str(info.get("authority_scope") or ""),
                )
                for session_key, info in self._sessions.items()
            )
            resolved = self._activity_resolver(sessions, self._covered_agents_locked())
            scoped = tuple(replace(session, session_id=key)
                           for key, session in zip(self._sessions, resolved, strict=True))
            snapshot = self._power_authority.snapshot(scoped)
            snapshot["scopes"] = [
                {
                    "agentId": key[0], "scope": key[1],
                    "generation": self._scope_generations.get(key, ""),
                    "orderToken": order.token,
                    "snapshotOrderToken": (
                        self._complete_snapshot_versions[key].token
                        if key in self._complete_snapshot_versions else None
                    ),
                    "leaseDeadlineNs": self._scope_lease_deadlines.get(key),
                    "replayed": key in self._replayed_scopes,
                    "reason": self._power_authority.scope_reason(*key),
                }
                for key, order in sorted(self._provider_versions.items())
            ]
            return snapshot

    def update_usage(
        self,
        *,
        usages: dict[str, dict[str, Any] | None] | None = None,
        clear_missing: bool = False,
    ) -> None:
        """Update per-agent usage caches.

        A ``None`` usage clears that agent's cache (the default agent resets
        to ``DEFAULT_USAGE`` instead of disappearing).
        """
        incoming: dict[str, dict[str, Any] | None] = dict(usages or {})

        with self._lock:
            if clear_missing:
                for agent_id in list(self._usage_caches):
                    if agent_id == self._default_agent_id:
                        continue
                    if agent_id not in incoming:
                        del self._usage_caches[agent_id]
            for agent_id, usage in incoming.items():
                aid = self.normalize_agent_id(agent_id)
                if usage is None:
                    if aid == self._default_agent_id:
                        self._usage_caches[aid] = dict(DEFAULT_USAGE)
                    else:
                        self._usage_caches.pop(aid, None)
                    continue
                current = self._usage_caches.setdefault(
                    aid,
                    dict(DEFAULT_USAGE) if aid == self._default_agent_id else {},
                )
                current.update(usage)

    def _meter_usage(self, agent_id: str,
                     usage: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
        if "monthly_pct" in usage and "weekly_pct" not in usage:
            display = self.agent_display_name(agent_id)
            return (
                {
                    "weekly_pct": usage.get("monthly_pct", 0.0),
                    "weekly_reset": usage.get("monthly_reset", "--"),
                    "weekly_reset_at": usage.get("monthly_reset_at", 0),
                    "session_pct": 0.0,
                    "session_reset": "--",
                    "session_reset_at": 0,
                },
                f"{display} Monthly",
                "",
            )
        weekly_title, session_title = self.agent_meter_titles(agent_id)
        # Blank the title of a window the agent doesn't report so the screen
        # hides that bar (it draws a meter only when its title is non-empty).
        if "weekly_pct" not in usage:
            weekly_title = ""
        if "session_pct" not in usage:
            session_title = ""
        return dict(usage), weekly_title, session_title

    def _per_agent_usage(self, snapshots: dict[str, dict[str, Any]]) -> dict[str, Any]:
        per_agent_usage: dict[str, Any] = {}
        for agent_id, usage in snapshots.items():
            if not usage:
                continue
            entry = {
                **usage,
                "agent_display": self.agent_display_name(agent_id),
            }
            limits = self._usage_limits(usage)
            if limits:
                entry["limits"] = limits
            per_agent_usage[agent_id] = entry
        return per_agent_usage

    def status_snapshot(self, pending_session_ids: set[str] | None = None) -> dict[str, Any]:
        sessions, status, per_agent_status, last_agent = self.overall_status(pending_session_ids)

        with self._lock:
            usage_snaps = {
                agent_id: dict(usage)
                for agent_id, usage in self._usage_caches.items()
            }

        last_usage = usage_snaps.get(last_agent)
        if last_usage:
            usage, weekly_title, session_title = self._meter_usage(
                last_agent, last_usage)
        else:
            # No usage info for the active agent: empty titles tell meter
            # clients (the screen) to hide the bars rather than show another
            # agent's numbers.
            usage = dict(DEFAULT_USAGE)
            weekly_title = ""
            session_title = ""
        per_agent_usage = self._per_agent_usage(usage_snaps)

        return {
            **usage,
            "sessions": sessions,
            "status": status,
            "per_agent_status": per_agent_status,
            "per_agent_usage": per_agent_usage,
            "last_active_agent": last_agent,
            "agent_id": last_agent,
            "agent_display": self.agent_display_name(last_agent),
            "weekly_title": weekly_title,
            "session_title": session_title,
        }

    @staticmethod
    def _usage_limits(usage: dict[str, Any]) -> list[dict[str, Any]]:
        # A meter is shown only for a window the agent actually reports, so a
        # limit the plan no longer has (e.g. Codex's 5-hour session window after
        # OpenAI's 2026-07 weekly-only change) disappears instead of showing 0%,
        # and reappears on its own once the window returns.
        limits = []
        if "weekly_pct" in usage:
            limits.append(CodelightState._usage_limit("Weekly", usage, "weekly"))
        if "session_pct" in usage:
            limits.append(CodelightState._usage_limit("Session", usage, "session"))
        if limits:
            return limits
        if "monthly_pct" in usage:
            return [CodelightState._usage_limit("Monthly", usage, "monthly")]
        return []

    @staticmethod
    def _usage_limit(label: str, usage: dict[str, Any], prefix: str) -> dict[str, Any]:
        return {
            "label": label,
            "pct": usage.get(f"{prefix}_pct", 0.0),
            "reset": usage.get(f"{prefix}_reset", "--"),
            "reset_at": usage.get(f"{prefix}_reset_at", 0),
        }

    def set_agent_capability(
        self,
        agent_id: str,
        key: str,
        value: Any,
    ) -> None:
        aid = self.normalize_agent_id(agent_id)
        with self._lock:
            usage = self._usage_caches.setdefault(
                aid,
                dict(DEFAULT_USAGE) if aid == self._default_agent_id else {},
            )
            usage[key] = value
