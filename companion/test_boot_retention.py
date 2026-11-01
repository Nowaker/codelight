import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from codelight_core.boot_epoch import BootIdentityUnavailable, BootPersistence, prune_previous_boots

CURRENT = "00000000-0000-4000-8000-000000000000"
DAY = 24 * 3600


def previous_boot(root: Path, index: int, days_ago: float) -> Path:
    directory = root / f"{index:08d}-1111-4111-8111-111111111111"
    (directory / "evidence.sqlite3.taints" / "scopes.taint" / "scope").mkdir(parents=True)
    (directory / "evidence.sqlite3.taints" / "scopes.taint" / "scope" / "marker.taint").touch()
    database = directory / "evidence.sqlite3"
    database.touch()
    used = time.time() - days_ago * DAY
    for path in (database, directory):
        os.utime(path, (used, used))
    return directory


class BootRetentionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.legacy = os.path.join(temporary.name, "evidence.sqlite3")
        self.root = Path(f"{self.legacy}.boots")
        self.current = self.root / CURRENT
        self.current.mkdir(parents=True)
        (self.current / "evidence.sqlite3").touch()
        identity = mock.patch("codelight_core.boot_epoch.boot_identity", return_value=CURRENT)
        identity.start()
        self.addCleanup(identity.stop)

    def remaining(self) -> list[str]:
        return sorted(child.name for child in self.root.iterdir())

    def test_keeps_the_current_boot_and_the_newest_recent_previous_boots(self):
        boots = [previous_boot(self.root, index, days_ago) for index, days_ago in enumerate((1, 2, 3, 30))]

        result = prune_previous_boots(self.legacy)

        self.assertEqual(self.remaining(), sorted([CURRENT, boots[0].name, boots[1].name]))
        self.assertEqual(result["kept"], [boots[0].name, boots[1].name])
        self.assertEqual(result["removed"], sorted([boots[2].name, boots[3].name]))
        self.assertEqual(result["failed"], [])

    def test_previous_boots_older_than_the_age_limit_are_removed_even_within_the_count(self):
        stale = previous_boot(self.root, 0, 19)

        result = prune_previous_boots(self.legacy)

        self.assertEqual(self.remaining(), [CURRENT])
        self.assertEqual(result["removed"], [stale.name])

    def test_the_current_boot_is_kept_even_when_it_looks_oldest(self):
        previous_boot(self.root, 0, 1)
        old = time.time() - 60 * DAY
        os.utime(self.current, (old, old))

        prune_previous_boots(self.legacy, keep=0)

        self.assertEqual(self.remaining(), [CURRENT])

    def test_unknown_current_boot_prunes_nothing(self):
        stale = previous_boot(self.root, 0, 60)

        with mock.patch("codelight_core.boot_epoch.boot_identity", side_effect=BootIdentityUnavailable):
            result = prune_previous_boots(self.legacy)

        self.assertIsNone(result["current"])
        self.assertTrue(stale.exists())

    def test_interrupted_deletes_are_finished_and_foreign_entries_are_left_alone(self):
        interrupted = self.root / ".prune-22222222-2222-4222-8222-222222222222"
        (interrupted / "evidence.sqlite3.taints").mkdir(parents=True)
        foreign = self.root / "not-a-boot"
        foreign.mkdir()

        result = prune_previous_boots(self.legacy)

        self.assertEqual(result["removed"], ["22222222-2222-4222-8222-222222222222"])
        self.assertEqual(self.remaining(), sorted([CURRENT, "not-a-boot"]))

    def test_missing_boot_directory_is_a_no_op(self):
        result = prune_previous_boots(os.path.join(self.root.parent, "absent.sqlite3"))

        self.assertEqual(result["removed"], [])


class NewEpochTriggerTests(unittest.TestCase):
    def test_only_the_process_publishing_the_boot_metadata_triggers_pruning(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = os.path.join(directory, "evidence.sqlite3")
            triggered = []
            with mock.patch("codelight_core.boot_epoch.boot_identity", return_value=CURRENT):
                first = BootPersistence(legacy, lambda: triggered.append("first"))
                second = BootPersistence(legacy, lambda: triggered.append("second"))
                first.verified_path()
                first.verified_path()
                second.verified_path()

            self.assertEqual(triggered, ["first"])


if __name__ == "__main__":
    unittest.main()
