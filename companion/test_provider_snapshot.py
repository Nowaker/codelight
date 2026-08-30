import time
import unittest

from codelight_core.power_authority import AuthoritySession
from codelight_core.state import CodelightState


class ProviderSnapshotStateTests(unittest.TestCase):
    def setUp(self):
        self.state = CodelightState(
            default_agent_id="opencode",
            agent_registry={"opencode": {"display": "OpenCode"}},
            idle_window=600,
            idle_window_waiting=30,
            agent_process_states=lambda agent_ids: {
                agent_id: True for agent_id in agent_ids
            },
        )
        self.state.set_enabled_agents({"opencode"})
        self.now = time.time()
        self.order = time.monotonic_ns()

    @staticmethod
    def sessions(*states):
        return tuple(
            AuthoritySession(session_id, "opencode", state)
            for session_id, state in states
        )

    def test_partial_idle_after_restart_does_not_prove_provider_idle(self):
        self.assertEqual(self.state.power_authority_snapshot()["state"], "unknown")

        self.state.update_session(
            "done",
            "idle",
            agent_id="opencode",
            observed_at=self.now,
            provider_evidence_complete=False,
        )

        self.assertEqual(self.state.power_authority_snapshot()["state"], "unknown")

    def test_complete_snapshots_replace_all_provider_activity(self):
        self.state.update_provider_snapshot(
            self.sessions(("busy", "working"), ("done", "idle")),
            agent_id="opencode",
            complete=True,
            observed_at=self.now,
        )
        self.assertEqual(self.state.power_authority_snapshot()["state"], "active")

        self.state.update_provider_snapshot(
            (),
            agent_id="opencode",
            complete=True,
            observed_at=self.now + 100.0,
        )

        self.assertEqual(self.state.power_authority_snapshot()["state"], "idle")

    def test_incomplete_snapshot_keeps_known_activity_but_cannot_prove_idle(self):
        self.state.update_provider_snapshot(
            self.sessions(("busy", "working")),
            agent_id="opencode",
            complete=False,
            observed_at=self.now,
        )
        self.assertEqual(self.state.power_authority_snapshot()["state"], "active")

        state = CodelightState(
            default_agent_id="opencode",
            agent_registry={"opencode": {"display": "OpenCode"}},
            idle_window=600,
            idle_window_waiting=30,
            agent_process_states=lambda agent_ids: {
                agent_id: True for agent_id in agent_ids
            },
        )
        state.set_enabled_agents({"opencode"})
        state.update_provider_snapshot(
            (),
            agent_id="opencode",
            complete=False,
            observed_at=self.now,
        )
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_older_complete_snapshot_does_not_clear_a_newer_event(self):
        self.state.update_session(
            "busy",
            "working",
            agent_id="opencode",
            observed_at=self.now + 100.0,
            order_token=self.order + 100,
            provider_evidence_complete=False,
        )

        self.state.update_provider_snapshot(
            (),
            agent_id="opencode",
            complete=True,
            observed_at=self.now,
            order_token=self.order,
        )

        self.assertEqual(self.state.power_authority_snapshot()["state"], "active")

    def test_event_older_than_complete_snapshot_does_not_resurrect_session(self):
        self.state.update_provider_snapshot(
            (),
            agent_id="opencode",
            complete=True,
            observed_at=self.now + 100.0,
            order_token=self.order + 100,
        )

        self.state.update_session(
            "busy",
            "working",
            agent_id="opencode",
            observed_at=self.now,
            order_token=self.order,
            provider_evidence_complete=False,
        )

        self.assertEqual(self.state.power_authority_snapshot()["state"], "idle")

    def test_complete_snapshot_only_replaces_its_process_directory_scope(self):
        self.state.update_provider_snapshot(
            self.sessions(("busy", "working")),
            agent_id="opencode",
            complete=True,
            observed_at=self.now,
            order_token=self.order + 100,
            authority_scope="process-a:/repo-a",
            authority_generation="process-a",
        )

        self.state.update_provider_snapshot(
            (),
            agent_id="opencode",
            complete=True,
            observed_at=self.now + 1.0,
            order_token=self.order + 200,
            authority_scope="process-b:/repo-b",
            authority_generation="process-b",
        )

        self.assertEqual(self.state.power_authority_snapshot()["state"], "active")

        self.state.update_provider_snapshot(
            (),
            agent_id="opencode",
            complete=True,
            observed_at=self.now + 2.0,
            order_token=self.order + 300,
            authority_scope="process-a:/repo-a",
            authority_generation="process-a",
        )
        self.assertEqual(self.state.power_authority_snapshot()["state"], "idle")

    def test_incomplete_live_scope_keeps_other_idle_scope_unknown(self):
        self.state.update_provider_snapshot(
            (),
            agent_id="opencode",
            complete=True,
            observed_at=self.now,
            order_token=self.order + 100,
            authority_scope="process-a:/repo-a",
            authority_generation="process-a",
        )
        self.state.update_provider_snapshot(
            (),
            agent_id="opencode",
            complete=False,
            observed_at=self.now + 1.0,
            order_token=self.order + 200,
            authority_scope="process-b:/repo-b",
            authority_generation="process-b",
        )

        self.assertEqual(self.state.power_authority_snapshot()["state"], "unknown")

    def test_expired_live_scope_lease_becomes_unknown(self):
        self.state.update_provider_snapshot(
            (),
            agent_id="opencode",
            complete=True,
            observed_at=self.now,
            order_token=self.order,
            authority_scope="process-a:/repo-a",
            authority_generation="process-a",
            lease_deadline_ns=time.monotonic_ns() - 1,
        )

        self.assertEqual(self.state.power_authority_snapshot()["state"], "unknown")

    def test_clock_rollback_uses_monotonic_event_order(self):
        self.state.update_provider_snapshot(
            (),
            agent_id="opencode",
            complete=True,
            observed_at=200.0,
            order_token=self.order,
        )
        self.state.update_session(
            "busy",
            "working",
            agent_id="opencode",
            observed_at=100.0,
            order_token=self.order + 1,
            provider_evidence_complete=False,
        )

        self.assertEqual(self.state.power_authority_snapshot()["state"], "active")

    def test_resolved_scope_does_not_clear_unbound_process_uncertainty(self):
        self.state.update_session(
            "done",
            "idle",
            agent_id="opencode",
            order_token=self.order,
            authority_scope="unresolved:opencode",
            provider_evidence_complete=False,
        )
        self.assertEqual(self.state.power_authority_snapshot()["state"], "unknown")

        self.state.update_session(
            "done",
            "idle",
            agent_id="opencode",
            order_token=self.order + 1,
            authority_scope="resolved-scope",
            authority_generation="resolved-generation",
            provider_evidence_complete=True,
        )

        self.assertEqual(self.state.power_authority_snapshot()["state"], "unknown")

    def test_restored_partial_session_keeps_its_own_causal_age(self):
        self.state.update_provider_snapshot(
            (
                AuthoritySession(
                    "busy",
                    "opencode",
                    "working",
                    observed_at=self.now - 1_000.0,
                    order_token=1,
                ),
            ),
            agent_id="opencode",
            complete=False,
            observed_at=self.now,
            order_token=self.order,
            authority_scope="process-a:/repo-a",
            authority_generation="process-a",
        )

        self.assertEqual(self.state.power_authority_snapshot()["state"], "unknown")

    def test_equal_tick_working_outranks_completion(self):
        self.state.update_session(
            "session-1",
            "working",
            agent_id="opencode",
            observed_at=self.now,
            order_token=self.order,
        )
        self.state.update_session(
            "session-1",
            "ended",
            agent_id="opencode",
            observed_at=self.now,
            order_token=self.order,
        )

        self.assertEqual(self.state.power_authority_snapshot()["state"], "active")


if __name__ == "__main__":
    unittest.main()
