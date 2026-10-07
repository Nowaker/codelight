import time
import uuid
from unittest import mock

import codelight
from codelight_core.evidence_order import UNKNOWN_RANK, evidence_order
from codelight_core.lifecycle import ProcessIdentity, authority_scope_key, process_generation_key
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.power_authority import AuthoritySession
from codelight_core.state import CodelightState
from test_opencode_question_activity import QuestionFixture


class GenerationAdmissionTests(QuestionFixture):
    def setUp(self) -> None:
        self.session("parent", question=True)
        self.store = LifecycleEvidenceStore(str(self.path.parent / "authority.sqlite3"))
        epoch = self.store.boot_id
        assert epoch is not None
        self.identities = {label: ProcessIdentity(pid, 1, f"generation:{label}", "/bin/opencode", "opencode", epoch)
                           for label, pid in (("a", 100), ("b", 200), ("c", 300))}
        self.state = self.new_state()
        self.send(self.record("a", parent=True))
        self.inventory(("a",))
        self.assertEqual(self.state.power_authority_snapshot()["state"], "idle")

    def new_state(self):
        state = CodelightState(default_agent_id="opencode", agent_registry={},
                               idle_window=60, idle_window_waiting=60,
                               activity_resolver=self.resolver.resolve)
        state.set_enabled_agents({"opencode"})
        return state

    def scope(self, label):
        return authority_scope_key("opencode", self.identities[label], "")

    def generation(self, label):
        return process_generation_key("opencode", self.identities[label])

    def inventory(self, labels):
        self.state.record_process_inventory("opencode", bool(labels))
        self.state.reconcile_replayed_authority(
            "opencode", frozenset(self.generation(label) for label in labels), frozenset(),
            evidence_order(time.monotonic_ns(), UNKNOWN_RANK),
        )

    def record(self, label, *, parent=False, event_only=False):
        token = time.monotonic_ns()
        operation = str(uuid.uuid4())
        if event_only:
            self.store.record(agent_id="opencode", identity=self.identities[label],
                              session_id="event", state="idle", hook_event="idle",
                              observed_at=time.time(), order_token=token, operation_id=operation)
        else:
            self.store.record_snapshot(
                agent_id="opencode", identity=self.identities[label], complete=True,
                sessions=(AuthoritySession("parent", "opencode", "working"),) if parent else (),
                observed_at=time.time(), order_token=token, operation_id=operation,
            )
        return {"agent_id": "opencode", "boot_id": self.store.boot_id,
                "authority_scope": self.scope(label), "authority_generation": self.generation(label),
                "order_token": token, "authority_rank": 2 if parent else 0, "operation_id": operation,
                "lease_deadline_ns": 9_223_372_036_854_775_807,
                "lifecycle_snapshot": {"complete": True,
                                       "sessions": [{"session_id": "parent", "state": "working"}] if parent else []}}

    def send(self, message):
        with (mock.patch.object(codelight, "_state", self.state),
              mock.patch.object(codelight, "_lifecycle_evidence_store", self.store),
              mock.patch.object(codelight, "_push_locked")):
            codelight._handle_socket_message(None, message)

    def assert_unknown(self):
        self.assertEqual(self.state.power_authority_snapshot()["state"], "unknown")

    def test_verified_new_generation_extends_known_inventory_immediately(self):
        self.send(self.record("c"))
        self.assertEqual(self.state.power_authority_snapshot()["state"], "idle")

    def test_unreported_existing_generation_is_not_removed_by_admission(self):
        self.inventory(("a", "b"))
        self.send(self.record("c"))
        self.assert_unknown()

    def test_successfully_empty_inventory_accepts_verified_first_generation(self):
        self.state = self.new_state()
        self.inventory(())
        self.send(self.record("c", parent=True))
        self.assertEqual(self.state.power_authority_snapshot()["state"], "idle")

    def test_failed_inventory_cannot_be_recreated_by_positive_evidence(self):
        self.state.record_process_inventory("opencode", None)
        self.send(self.record("c"))
        self.assert_unknown()
        self.assertNotIn("opencode", self.state._live_generations)

    def test_generic_complete_snapshot_does_not_admit_generation(self):
        self.state.update_provider_snapshot((), agent_id="opencode", complete=True,
            observed_at=time.time(), authority_scope=self.scope("c"), authority_generation=self.generation("c"),
            lease_deadline_ns=9_223_372_036_854_775_807)
        self.assert_unknown()

    def test_caller_verified_flag_without_durable_proof_is_ignored(self):
        self.send({"agent_id": "opencode", "boot_id": self.store.boot_id,
                   "authority_scope": self.scope("c"), "authority_generation": self.generation("c"),
                   "verified_generation": True, "lease_deadline_ns": 9_223_372_036_854_775_807,
                   "lifecycle_snapshot": {"complete": True, "sessions": []}})
        self.assert_unknown()

    def test_event_only_durable_record_is_not_snapshot_proof(self):
        self.send(self.record("c", event_only=True))
        self.assert_unknown()

    def test_incomplete_message_does_not_admit_generation(self):
        message = self.record("c")
        self.send({**message, "lifecycle_snapshot": {"complete": False, "sessions": []}})
        self.assert_unknown()
        self.assertNotIn(self.generation("c"), self.state._live_generations["opencode"])

    def test_newer_durable_snapshot_corroborates_membership(self):
        message = self.record("c")
        self.record("c")
        self.send(message)
        self.assertEqual(self.state.power_authority_snapshot()["state"], "idle")

    def test_stale_rejected_message_cannot_admit_generation(self):
        message = self.record("c")
        self.state.update_provider_snapshot((), agent_id="opencode", complete=True,
            observed_at=time.time(), order_token=time.monotonic_ns(),
            authority_scope=self.scope("c"), authority_generation=self.generation("c"))
        self.send(message)
        self.assert_unknown()
        self.assertNotIn(self.generation("c"), self.state._live_generations["opencode"])

    def test_pending_gate_is_not_cleared_by_admission(self):
        self.state.begin_authority_restore({"opencode"})
        self.inventory(("a",))
        self.send(self.record("c"))
        self.assert_unknown()
        self.state.finish_authority_restore({"opencode"})
        self.assertEqual(self.state.power_authority_snapshot()["state"], "idle")

    def test_other_scope_uncertainty_is_not_cleared_by_admission(self):
        self.state.update_provider_snapshot((), agent_id="opencode", complete=False,
            observed_at=time.time(), authority_scope=self.scope("a"))
        self.send(self.record("c"))
        self.assert_unknown()

    def test_process_uncertainty_is_not_cleared_by_admission(self):
        self.state._power_authority.record_process_state("opencode", None)
        self.send(self.record("c"))
        self.assertIn(self.generation("c"), self.state._live_generations["opencode"])
        self.assert_unknown()

    def test_event_after_complete_snapshot_does_not_prove_current_snapshot(self):
        self.record("c")
        self.send(self.record("c", event_only=True))
        self.assert_unknown()

    def test_expired_durable_snapshot_cannot_be_corroborated_by_live_message_lease(self):
        message = self.record("c")
        self.store.record_snapshot(agent_id="opencode", identity=self.identities["c"],
            sessions=(), complete=True, observed_at=time.time(), order_token=time.monotonic_ns(),
            lease_deadline_ns=time.monotonic_ns() - 1)
        self.send(message)
        self.assert_unknown()

    def test_mismatched_scope_does_not_admit_verified_generation(self):
        self.send({**self.record("c"), "authority_scope": "unbound-scope"})
        self.assert_unknown()

    def test_mismatched_generation_does_not_admit_verified_scope(self):
        self.send({**self.record("c"), "authority_generation": "unbound-generation"})
        self.assert_unknown()

    def test_foreign_boot_message_cannot_admit_generation(self):
        self.send({**self.record("c"), "boot_id": "foreign-boot"})
        self.assertEqual(self.state._live_generations["opencode"], frozenset({self.generation("a")}))

    def test_replay_cannot_use_positive_socket_admission(self):
        self.state.update_provider_snapshot((), agent_id="opencode", complete=True,
            observed_at=time.time(), authority_scope=self.scope("c"), authority_generation=self.generation("c"),
            replayed=True, verified_generation=True)
        self.assertNotIn(self.generation("c"), self.state._live_generations["opencode"])
        self.assert_unknown()

    def test_durable_uncertainty_cannot_be_bypassed_before_next_replay(self):
        message = self.record("c")
        self.store.invalidate_agent("opencode", time.monotonic_ns())
        self.send(message)
        self.assert_unknown()

    def test_recovered_historical_taints_do_not_block_positive_admission(self):
        self.store.invalidate_agent("opencode", time.monotonic_ns())
        self.record("a", parent=True)
        message = self.record("c")
        self.store.replay_inventory(
            {"opencode": frozenset({self.identities["a"], self.identities["c"]})},
            evidence_order(time.monotonic_ns(), UNKNOWN_RANK),
        )
        self.send(message)
        self.assertEqual(self.state.power_authority_snapshot()["state"], "idle")
