import os
import tempfile
import time
import unittest
from collections.abc import Callable
from unittest import mock

import codelight
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.state import CodelightState


ProcessScan = Callable[
    [set[str]],
    dict[str, frozenset[ProcessIdentity]] | None,
]


def process() -> ProcessIdentity:
    return ProcessIdentity(
        pid=100,
        ppid=1,
        started_at="darwin:1788076913:123456",
        executable="/opt/homebrew/bin/codex",
        command="/opt/homebrew/bin/codex",
    )


class InventoryInvalidationRecoveryTests(unittest.TestCase):
    @staticmethod
    def state() -> CodelightState:
        state = CodelightState(
            default_agent_id="codex",
            agent_registry={"codex": {"display": "Codex"}},
            idle_window=600,
            idle_window_waiting=30,
            agent_process_states=lambda agent_ids: {
                agent_id: True for agent_id in agent_ids
            },
        )
        state.set_enabled_agents({"codex"})
        return state

    def restore(
        self,
        store: LifecycleEvidenceStore,
        identity: ProcessIdentity,
        inventory_token: int,
        scan: ProcessScan | None = None,
    ) -> CodelightState:
        state = self.state()
        process_scan = scan or (
            lambda _agent_ids: {"codex": frozenset({identity})}
        )
        with (
            mock.patch.object(codelight, "_state", state),
            mock.patch.object(
                codelight.time,
                "monotonic_ns",
                return_value=inventory_token,
            ),
            mock.patch.object(
                codelight._agent_process_probe,
                "identities",
                side_effect=process_scan,
            ),
            mock.patch.object(codelight, "_lifecycle_evidence_store", store),
        ):
            codelight._restore_lifecycle_evidence({"codex"})
        return state

    @staticmethod
    def record_idle(
        store: LifecycleEvidenceStore,
        identity: ProcessIdentity,
        order_token: int,
    ) -> None:
        store.record_snapshot(
            agent_id="codex",
            identity=identity,
            sessions=(),
            complete=True,
            observed_at=time.time(),
            order_token=order_token,
            operation_id="known-idle",
        )

    def test_successful_inventory_clears_older_scan_failure(self):
        identity = process()
        inventory_token = time.monotonic_ns()
        with tempfile.TemporaryDirectory() as tmp:
            store = LifecycleEvidenceStore(os.path.join(tmp, "evidence.sqlite3"))
            self.record_idle(store, identity, inventory_token - 2)
            self.restore(
                store,
                identity,
                inventory_token - 1,
                lambda _agent_ids: None,
            )

            state = self.restore(store, identity, inventory_token)

            replay = store.replay(
                {"codex": frozenset({identity})},
                now_order_token=inventory_token,
            )[0]

        self.assertTrue(replay.complete)
        self.assertEqual(state.power_authority_snapshot()["state"], "idle")

    def test_successful_inventory_preserves_newer_scan_failure(self):
        identity = process()
        inventory_token = time.monotonic_ns()
        with tempfile.TemporaryDirectory() as tmp:
            store = LifecycleEvidenceStore(os.path.join(tmp, "evidence.sqlite3"))
            self.record_idle(store, identity, inventory_token - 1)

            def scan_with_concurrent_failure(
                _agent_ids: set[str],
            ) -> dict[str, frozenset[ProcessIdentity]]:
                store.invalidate_inventory_scan_failure(
                    "codex",
                    inventory_token + 1,
                    "after-process-scan",
                )
                return {"codex": frozenset({identity})}

            state = self.restore(
                store,
                identity,
                inventory_token,
                scan_with_concurrent_failure,
            )

            replay = store.replay(
                {"codex": frozenset({identity})},
                now_order_token=inventory_token,
            )[0]

        self.assertFalse(replay.complete)
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_successful_inventory_preserves_equal_token_scan_failure(self):
        identity = process()
        inventory_token = time.monotonic_ns()
        with tempfile.TemporaryDirectory() as tmp:
            store = LifecycleEvidenceStore(os.path.join(tmp, "evidence.sqlite3"))
            self.record_idle(store, identity, inventory_token - 1)
            store.invalidate_inventory_scan_failure(
                "codex",
                inventory_token,
                "equal-to-process-scan",
            )

            state = self.restore(store, identity, inventory_token)

            replay = store.replay(
                {"codex": frozenset({identity})},
                now_order_token=inventory_token,
            )[0]

        self.assertFalse(replay.complete)
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_successful_inventory_preserves_older_hook_invalidation(self):
        identity = process()
        inventory_token = time.monotonic_ns()
        with tempfile.TemporaryDirectory() as tmp:
            store = LifecycleEvidenceStore(os.path.join(tmp, "evidence.sqlite3"))
            self.record_idle(store, identity, inventory_token - 2)
            store.invalidate_agent(
                "codex",
                inventory_token - 1,
                "unresolved-hook-identity",
            )

            state = self.restore(store, identity, inventory_token)

            replay = store.replay(
                {"codex": frozenset({identity})},
                now_order_token=inventory_token,
            )[0]

        self.assertFalse(replay.complete)
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_successful_inventory_preserves_legacy_invalidation(self):
        identity = process()
        inventory_token = time.monotonic_ns()
        with tempfile.TemporaryDirectory() as tmp:
            store = LifecycleEvidenceStore(os.path.join(tmp, "evidence.sqlite3"))
            self.record_idle(store, identity, inventory_token - 2)
            store.invalidate_agent(
                "codex",
                inventory_token - 1,
                "legacy-untagged",
            )

            state = self.restore(store, identity, inventory_token)

            replay = store.replay(
                {"codex": frozenset({identity})},
                now_order_token=inventory_token,
            )[0]

        self.assertFalse(replay.complete)
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_exact_absence_preserves_equal_token_invalidation(self):
        identity = process()
        order_token = time.monotonic_ns()
        with tempfile.TemporaryDirectory() as tmp:
            store = LifecycleEvidenceStore(os.path.join(tmp, "evidence.sqlite3"))
            self.record_idle(store, identity, order_token - 1)
            store.invalidate_agent("codex", order_token, "equal-uncertainty")

            store.clear_agent_invalidation(
                "codex",
                order_token,
                "exact-absence",
            )

            replay = store.replay(
                {"codex": frozenset({identity})},
                now_order_token=order_token,
            )[0]

        self.assertFalse(replay.complete)


if __name__ == "__main__":
    unittest.main()
