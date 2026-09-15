import tempfile
import unittest
from unittest import mock
from pathlib import Path
import time
import json

import codelight

from codelight_core import boot_epoch
from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_taint import GenerationTaintStore
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.state import CodelightState
from codelight_core.power_status_file import PowerStatusPublisher


class TaintBootLookupTests(unittest.TestCase):
    def test_scope_cleanup_does_not_parse_unrelated_historical_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            store = GenerationTaintStore(directory)
            identity = ProcessIdentity(100, 1, "generation", "opencode", "opencode")
            for token in range(20):
                store.mark("opencode", identity, "other-scope", EvidenceOrder(token, 1, str(token)))
            store.mark("opencode", identity, "own-scope", EvidenceOrder(20, 1, "own"))
            with mock.patch.object(store._files, "_parse", wraps=store._files._parse) as parse:
                store.clear_scope_through("opencode", identity, "own-scope", EvidenceOrder(21, 1, "done"))
            self.assertEqual(parse.call_count, 1)
            remaining, malformed = store.attempts()
            self.assertFalse(malformed)
            self.assertEqual(len(remaining), 20)
            self.assertTrue(all(item.scope_id == "other-scope" for item in remaining))

    def test_pending_inventory_publishes_unknown_without_parsing_historical_backlog(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LifecycleEvidenceStore(str(Path(directory) / "authority.sqlite3"))
            identity = ProcessIdentity(100, 1, "generation", "opencode", "opencode")
            store.record_snapshot(agent_id="opencode", identity=identity, sessions=(), complete=True,
                                  observed_at=time.time(), order_token=time.monotonic_ns())
            taints = Path(store._path + ".taints")
            taints.mkdir(exist_ok=True)
            (taints / f".{('a' * 64)}.{('b' * 64)}-00000000000000000100-1-pending.taint.nonce.tmp").touch()
            for token in range(20):
                store._taints.mark("opencode", identity, "scope", EvidenceOrder(token, 1, str(token)))
            with mock.patch.object(store._taints._files, "_parse", wraps=store._taints._files._parse) as parse:
                replay = store.replay_inventory({"opencode": frozenset({identity})},
                                               EvidenceOrder(time.monotonic_ns(), 1, "scan"))
                state = CodelightState(default_agent_id="opencode", agent_registry={},
                                       idle_window=60, idle_window_waiting=60)
                state.set_enabled_agents({"opencode"})
                status = Path(directory) / "power-status.json"
                status.write_text('{"observedAt":0}')
                before = time.time()
                with (mock.patch.object(codelight, "_state", state),
                      mock.patch.object(codelight, "_lifecycle_evidence_store", store),
                      mock.patch.object(codelight._agent_process_probe, "identities",
                                        return_value={"opencode": frozenset({identity})}),
                      mock.patch.object(codelight, "_power_status_publisher", PowerStatusPublisher(str(status))),
                      mock.patch.object(codelight, "_status_snapshot", return_value={}),
                      mock.patch.object(codelight, "_broadcast")):
                    codelight._restore_lifecycle_evidence({"opencode"})
                    codelight._push()
                published = json.loads(status.read_text())
                self.assertGreaterEqual(published["observedAt"], before)
                self.assertEqual(published["state"], "unknown")
            self.assertEqual(replay.failure_reason, "taint-inventory-incomplete")
            self.assertEqual(replay.stale_inventory_agents, frozenset({"opencode"}))
            self.assertFalse(replay.providers[0].complete)
            self.assertEqual(parse.call_count, 0)

    def test_scope_inventory_does_not_query_os_boot_for_each_historical_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            epoch = boot_epoch.boot_identity()
            identity = ProcessIdentity(100, 1, "generation", "opencode", "opencode", epoch)
            writer = GenerationTaintStore(directory)
            for token in range(20):
                writer.mark("opencode", identity, "scope", EvidenceOrder(token, 1, str(token)))
            with mock.patch.object(boot_epoch, "boot_identity", return_value=epoch) as lookup:
                reader = GenerationTaintStore(directory)
                first, malformed = reader.attempts()
                second, malformed_again = reader.attempts()
            self.assertFalse(malformed or malformed_again)
            self.assertEqual(len(first), 20)
            self.assertEqual(first, second)
            self.assertTrue(all(item.identity == identity for item in first))
            self.assertLessEqual(lookup.call_count, 1)
