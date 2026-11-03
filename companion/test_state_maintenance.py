import fcntl
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from codelight_core.boot_epoch import MAINTENANCE_INTERVAL_SECONDS, MAINTENANCE_STAMP, BootPersistence
from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle_evidence_taint import GenerationTaintStore
from codelight_core.lifecycle_evidence_taint_io import SCOPE_CONTAINER
from codelight_core.state_maintenance import MAINTENANCE_LOCK, maintain_state
from test_boot_retention import CURRENT, DAY, previous_boot
from test_taint_compaction import DEAD, LIVE, age, alive


class MaintenanceTestCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.monitor = Path(temporary.name, "monitor_state")
        self.monitor.mkdir()
        self.legacy = str(self.monitor / "evidence.sqlite3")
        self.root = Path(f"{self.legacy}.boots")
        identity = mock.patch("codelight_core.boot_epoch.boot_identity", return_value=CURRENT)
        identity.start()
        self.addCleanup(identity.stop)


class MaintenanceTriggerTests(MaintenanceTestCase):
    def requests(self) -> int:
        requested = []
        BootPersistence(self.legacy, lambda: requested.append(True)).verified_path()
        return len(requested)

    def test_maintenance_is_requested_by_the_new_boot_and_then_once_per_interval(self):
        self.assertEqual(self.requests(), 1)
        self.assertEqual(self.requests(), 0)

        overdue = time.time() - MAINTENANCE_INTERVAL_SECONDS - 1
        os.utime(self.root / MAINTENANCE_STAMP, (overdue, overdue))

        self.assertEqual(self.requests(), 1)
        self.assertEqual(self.requests(), 0)


class MaintainStateTests(MaintenanceTestCase):
    def maintain(self):
        return maintain_state(self.legacy, str(self.monitor), ("opencode",), generation_alive=alive)

    def test_bounds_previous_boots_dead_scope_evidence_and_stale_fallback_states(self):
        stale_boot = previous_boot(self.root, 0, 30)
        taints = self.root / CURRENT / "evidence.sqlite3.taints"
        store = GenerationTaintStore(str(taints))
        live = store.mark("opencode", LIVE, "live-scope", EvidenceOrder(1, 0, "live"))
        store.mark("opencode", DEAD, "dead-scope", EvidenceOrder(2, 0, "dead"))
        (taints / SCOPE_CONTAINER / ("0" * 64)).mkdir()
        age(str(taints))
        stale_state = self.monitor / "ses_stale.json"
        fresh_state = self.monitor / "ses_fresh.json"
        for path in (stale_state, fresh_state):
            path.write_text("{}")
        old = time.time() - 30 * DAY
        os.utime(stale_state, (old, old))

        result = self.maintain()

        self.assertFalse(stale_boot.exists())
        self.assertEqual(os.listdir(taints / SCOPE_CONTAINER), [os.path.basename(os.path.dirname(live.path))])
        self.assertFalse(stale_state.exists())
        self.assertTrue(fresh_state.exists())
        self.assertEqual(result["fallback-states-removed"], 1)
        self.assertLess(time.time() - (self.root / MAINTENANCE_STAMP).stat().st_mtime, 60)

    def test_a_concurrent_run_is_skipped(self):
        stale_boot = previous_boot(self.root, 0, 30)

        with open(self.root / MAINTENANCE_LOCK, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.maintain()

        self.assertEqual(result, {"skipped": "already running"})
        self.assertTrue(stale_boot.exists())


if __name__ == "__main__":
    unittest.main()
