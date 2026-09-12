import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
import uuid

import codelight
from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.lifecycle_evidence_taint import GenerationTaintStore
from codelight_core.state import CodelightState


class ReplayTaintRescanTests(unittest.TestCase):
    def replay_interleaving(self, *, promotion: bool):
        with tempfile.TemporaryDirectory() as directory:
            store = LifecycleEvidenceStore(str(Path(directory) / "authority.sqlite3"))
            identity = ProcessIdentity(100, 1, "generation", "opencode", "opencode")
            base = time.monotonic_ns()
            store.record_snapshot(agent_id="opencode", identity=identity, sessions=(),
                                  complete=True, observed_at=time.time(), order_token=base)
            state = CodelightState(default_agent_id="opencode", agent_registry={},
                                   idle_window=60, idle_window_waiting=60)
            state.set_enabled_agents({"opencode"})
            with (mock.patch.object(codelight, "_state", state),
                  mock.patch.object(codelight, "_lifecycle_evidence_store", store),
                  mock.patch.object(codelight._agent_process_probe, "identities",
                                    return_value={"opencode": frozenset({identity})})):
                codelight._restore_lifecycle_evidence({"opencode"})
                self.assertEqual(state.power_authority_snapshot()["state"], "idle")
                taints = Path(store._path + ".taints")
                taints.mkdir(exist_ok=True)
                if promotion:
                    original_path = taints / "unordered.taint"
                    original_path.write_text(json.dumps({
                        "kind": "agent", "agent_id": "opencode", "authority_rank": 1,
                        "order_token": None, "operation_id": f"transport-failed-{uuid.uuid4()}",
                    }))
                else:
                    marker = store._taints.mark("opencode", identity, "", EvidenceOrder(base - 1, 0, "finishing"))
                    original_path = Path(marker.path)
                parse = store._taints._files._parse
                raced = False

                def competing_writer(path):
                    nonlocal raced
                    if not raced:
                        raced = True
                        if promotion:
                            GenerationTaintStore(str(taints)).attempts()
                        else:
                            original_path.unlink()
                    return parse(path)

                original_replay = store.replay_inventory
                results = []

                def capture_replay(live, order):
                    replay = original_replay(live, order)
                    results.append(replay)
                    return replay

                with (mock.patch.object(store._taints._files, "_parse", side_effect=competing_writer),
                      mock.patch.object(store, "replay_inventory", side_effect=capture_replay)):
                    codelight._restore_lifecycle_evidence({"opencode"})
                self.assertTrue(raced)
                self.assertEqual(len(results), 1)
                return results[0], state.power_authority_snapshot()

    def test_completed_writer_disappearance_restores_complete_provider(self):
        replay, snapshot = self.replay_interleaving(promotion=False)
        self.assertEqual(len(replay.providers), 1)
        self.assertEqual(sum(provider.complete for provider in replay.providers), 1)
        self.assertEqual(replay.stale_inventory_agents, frozenset())
        self.assertEqual(snapshot["state"], "idle")

    def test_promoted_transport_failure_invalidates_previously_idle_provider(self):
        replay, snapshot = self.replay_interleaving(promotion=True)
        self.assertEqual(len(replay.providers), 1)
        self.assertEqual(sum(provider.complete for provider in replay.providers), 0)
        self.assertGreater(replay.providers[0].order_token, 0)
        self.assertEqual(replay.stale_inventory_agents, frozenset({"opencode"}))
        self.assertEqual(snapshot["state"], "unknown")
