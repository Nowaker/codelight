"""Current authority, not historical SQLite execution, owns descendant activity."""
import time

from test_opencode_question_activity import QuestionFixture
from codelight_core.evidence_order import evidence_order, UNKNOWN_RANK
from codelight_core.power_authority import AuthoritySession
from codelight_core.state import CodelightState


class CoverageTests(QuestionFixture):
    def authority(self, children=(), *, complete=True, expired=False, generations=None):
        state = CodelightState(
            default_agent_id="opencode", agent_registry={}, idle_window=60,
            idle_window_waiting=60, activity_resolver=self.resolver.resolve,
        )
        state.set_enabled_agents({"opencode"})
        now = time.monotonic_ns()
        state.update_provider_snapshot(
            (AuthoritySession("parent", "opencode", "working"), *children),
            agent_id="opencode", complete=complete, authority_scope="scope",
            authority_generation="generation", order_token=now, observed_at=time.time(),
            lease_deadline_ns=now - 1 if expired else now + 60_000_000_000,
        )
        state.record_process_inventory("opencode", True)
        state.reconcile_replayed_authority(
            "opencode", generations or frozenset({"generation"}), frozenset(),
            evidence_order(now + 1, UNKNOWN_RANK),
        )
        return state

    def test_historical_unfinished_child_is_not_current_execution(self):
        self.session("parent", question=True)
        self.session("child", "parent")
        self.assertEqual(self.authority().power_authority_snapshot()["state"], "idle")

    def test_current_working_child_remains_busy(self):
        self.session("parent", question=True)
        self.session("child", "parent")
        state = self.authority((AuthoritySession("child", "opencode", "working"),))
        self.assertEqual(state.power_authority_snapshot()["state"], "active")

    def test_second_unreported_generation_prevents_idle(self):
        self.session("parent", question=True)
        state = self.authority(generations=frozenset({"generation", "unreported"}))
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_incomplete_coverage_prevents_idle(self):
        self.session("parent", question=True)
        self.session("child", "parent")
        self.assertEqual(self.authority(complete=False).power_authority_snapshot()["state"], "unknown")

    def test_expired_coverage_prevents_idle(self):
        self.session("parent", question=True)
        self.assertEqual(self.authority(expired=True).power_authority_snapshot()["state"], "unknown")

    def test_live_grandchild_through_historical_middle_keeps_parent_busy(self):
        self.session("parent", question=True)
        self.session("middle", "parent")
        self.session("grandchild", "middle")
        state = self.authority((AuthoritySession("grandchild", "opencode", "working"),))
        self.assertEqual(state.power_authority_snapshot()["providers"]["opencode"]["activeSessions"], 2)

    def test_dangling_grandparent_prevents_idle(self):
        self.session("parent", "ancestor", question=True)
        self.session("ancestor", "missing", completed=True)
        self.assertEqual(self.authority().power_authority_snapshot()["state"], "unknown")

    def test_ancestor_cycle_prevents_idle(self):
        self.session("parent", "ancestor", question=True)
        self.session("ancestor", "other", completed=True)
        self.session("other", "ancestor", completed=True)
        self.assertEqual(self.authority().power_authority_snapshot()["state"], "unknown")

    def test_restore_batch_withholds_coverage_until_finalized(self):
        self.session("parent", question=True)
        state = self.authority()
        state.begin_authority_restore({"opencode"})
        state.reconcile_replayed_authority(
            "opencode", frozenset({"generation"}), frozenset(),
            evidence_order(time.monotonic_ns(), UNKNOWN_RANK),
        )
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")
        state.finish_authority_restore({"opencode"})
        self.assertEqual(state.power_authority_snapshot()["state"], "idle")

    def test_failed_inventory_withholds_previous_coverage(self):
        self.session("parent", question=True)
        state = self.authority()
        state.record_process_inventory("opencode", None)
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_delta_after_snapshot_withholds_coverage(self):
        self.session("parent", question=True)
        state = self.authority()
        state.update_session("parent", "working", agent_id="opencode",
                             authority_scope="scope", authority_generation="generation")
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_default_empty_coverage_cannot_publish_idle(self):
        self.session("parent", question=True)
        result = self.resolver.resolve((AuthoritySession("parent", "opencode", "working"),))
        self.assertEqual(result[0].state, "unknown")
