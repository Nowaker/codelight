import time
import unittest

from codelight_core.lifecycle_snapshot import (
    _NO_EXPIRY_NS,
    _SNAPSHOT_LEASE_NS,
    ProviderSnapshot,
    snapshot_lease_deadline_ns,
)
from codelight_core.power_authority import AuthoritySession
from codelight_core.state import CodelightState


AGENT = "opencode"
SCOPE = "opencode:1:darwin:1:/tmp/x"


def working(session_id: str) -> AuthoritySession:
    return AuthoritySession(session_id, AGENT, "working")


def live_agent_state() -> CodelightState:
    state = CodelightState(
        default_agent_id=AGENT,
        agent_registry={AGENT: {"display": "OpenCode"}},
        idle_window=600,
        idle_window_waiting=30,
        agent_process_states=lambda agent_ids: {
            agent_id: True for agent_id in agent_ids
        },
    )
    state.set_enabled_agents({AGENT})
    return state


def publish_snapshot(
    state: CodelightState,
    sessions: tuple[AuthoritySession, ...],
    complete: bool,
    order_token: int,
) -> None:
    state.update_provider_snapshot(
        sessions,
        agent_id=AGENT,
        complete=complete,
        observed_at=time.time(),
        order_token=order_token,
        authority_scope=SCOPE,
        authority_generation="gen-1",
        lease_deadline_ns=snapshot_lease_deadline_ns(
            ProviderSnapshot(complete, sessions),
            order_token,
        ),
    )


class SnapshotLeaseDeadlineTests(unittest.TestCase):
    def test_complete_idle_snapshot_never_expires(self):
        deadline = snapshot_lease_deadline_ns(ProviderSnapshot(True, ()), 1000)

        self.assertEqual(deadline, _NO_EXPIRY_NS)

    def test_complete_snapshot_with_active_session_expires(self):
        snapshot = ProviderSnapshot(True, (working("session-1"),))

        deadline = snapshot_lease_deadline_ns(snapshot, 1000)

        self.assertEqual(deadline, 1000 + _SNAPSHOT_LEASE_NS)

    def test_incomplete_snapshot_expires(self):
        deadline = snapshot_lease_deadline_ns(ProviderSnapshot(False, ()), 1000)

        self.assertEqual(deadline, 1000 + _SNAPSHOT_LEASE_NS)


class QuietLiveAgentTests(unittest.TestCase):
    """A live agent that simply has nothing to report must not decay to unknown.

    Long-lived idle TUI processes stop emitting snapshots, so an expiring idle
    claim leaves an uncertain scope no later evidence can clear while the agent
    stays alive - the machine then never sleeps.
    """

    def elapsed_token(self) -> int:
        return time.monotonic_ns() - 60 * 1_000_000_000

    def test_quiet_live_agent_stays_idle_past_lease_interval(self):
        state = live_agent_state()
        publish_snapshot(state, (), True, self.elapsed_token())

        snapshot = state.power_authority_snapshot()

        self.assertEqual(snapshot["state"], "idle")
        self.assertEqual(snapshot["providers"][AGENT]["state"], "idle")

    def test_stale_active_snapshot_still_fails_closed(self):
        state = live_agent_state()
        publish_snapshot(
            state,
            (working("session-1"),),
            True,
            self.elapsed_token(),
        )

        snapshot = state.power_authority_snapshot()

        self.assertEqual(snapshot["state"], "unknown")

    def test_incomplete_snapshot_still_fails_closed(self):
        state = live_agent_state()
        publish_snapshot(state, (), False, self.elapsed_token())

        snapshot = state.power_authority_snapshot()

        self.assertEqual(snapshot["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
