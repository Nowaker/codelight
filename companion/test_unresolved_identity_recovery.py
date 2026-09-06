import time
import unittest

from codelight_core.evidence_order import UNKNOWN_RANK, evidence_order
from codelight_core.state import CodelightState


AGENT = "opencode"
UNRESOLVED = f"unresolved:{AGENT}"
NO_EXPIRY = 9_223_372_036_854_775_807


def live_state() -> CodelightState:
    state = CodelightState(
        default_agent_id=AGENT,
        agent_registry={AGENT: {"display": "OpenCode"}},
        idle_window=600,
        idle_window_waiting=30,
        agent_process_states=lambda agent_ids: {a: True for a in agent_ids},
    )
    state.set_enabled_agents({AGENT})
    return state


def scope_of(pid: int) -> str:
    return f"{AGENT}:{pid}:darwin:1:/tmp/p{pid}"


def generation_of(pid: int) -> str:
    return f"{AGENT}:{pid}:darwin:1"


def publish_idle(state: CodelightState, pid: int, order_token: int) -> None:
    state.update_provider_snapshot(
        (),
        agent_id=AGENT,
        complete=True,
        observed_at=time.time(),
        order_token=order_token,
        authority_scope=scope_of(pid),
        authority_generation=generation_of(pid),
        lease_deadline_ns=NO_EXPIRY,
    )


def orphaned_hook_event(state: CodelightState, order_token: int) -> None:
    state.update_session(
        "ses-orphan",
        "idle",
        agent_id=AGENT,
        observed_at=time.time(),
        provider_evidence_complete=False,
        order_token=order_token,
        authority_scope=UNRESOLVED,
        authority_generation="",
    )


def reconcile(
    state: CodelightState,
    pids: tuple[int, ...],
    order_token: int,
) -> None:
    state.reconcile_replayed_authority(
        AGENT,
        frozenset(generation_of(pid) for pid in pids),
        frozenset(scope_of(pid) for pid in pids),
        evidence_order(order_token, UNKNOWN_RANK, "inventory"),
    )


class UnresolvedIdentityRecoveryTests(unittest.TestCase):
    """An event whose process could not be identified must not poison forever.

    A hook orphaned by its exiting agent resolves no identity, so it claims the
    agent-wide ``unresolved:`` scope. That scope carries no generation, nothing
    republishes it, and every live agent process blocks the absence path - so
    the claim outlives any amount of later evidence until the daemon restarts.
    """

    def test_orphaned_event_is_uncertain_until_live_processes_report(self):
        state = live_state()
        base = time.monotonic_ns()
        publish_idle(state, 100, base)

        orphaned_hook_event(state, base + 1)

        snapshot = state.power_authority_snapshot()
        self.assertEqual(snapshot["state"], "unknown")
        self.assertEqual(snapshot["providers"][AGENT]["activeSessions"], 0)

    def test_later_complete_evidence_from_every_live_process_resolves_it(self):
        state = live_state()
        base = time.monotonic_ns()
        publish_idle(state, 100, base)
        orphaned_hook_event(state, base + 1)

        publish_idle(state, 100, base + 2)
        reconcile(state, (100,), base + 3)

        snapshot = state.power_authority_snapshot()
        self.assertEqual(snapshot["state"], "idle")
        self.assertEqual(snapshot["reason"], "all-sessions-complete")

    def test_every_live_process_must_report_after_the_claim(self):
        state = live_state()
        base = time.monotonic_ns()
        publish_idle(state, 100, base)
        publish_idle(state, 200, base + 1)
        orphaned_hook_event(state, base + 2)

        publish_idle(state, 100, base + 3)
        reconcile(state, (100, 200), base + 4)

        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_evidence_older_than_the_claim_does_not_resolve_it(self):
        state = live_state()
        base = time.monotonic_ns()
        publish_idle(state, 100, base)
        orphaned_hook_event(state, base + 5)

        reconcile(state, (100,), base + 6)

        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_silent_live_process_keeps_the_claim(self):
        state = live_state()
        base = time.monotonic_ns()
        publish_idle(state, 100, base)
        orphaned_hook_event(state, base + 1)
        publish_idle(state, 100, base + 2)

        reconcile(state, (100, 300), base + 3)

        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
