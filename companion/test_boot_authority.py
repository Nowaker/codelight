import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.evidence_order import EvidenceOrder
from codelight_core.boot_epoch import BootIdentityUnavailable, BootPersistence


class BootAuthorityTests(unittest.TestCase):
    def test_foreign_origin_identity_cannot_be_relabelled_by_new_store(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = ProcessIdentity(123, 1, 'generation', '/agent', '', 'old-boot')
            store = LifecycleEvidenceStore(str(Path(directory) / 'authority.sqlite3'))
            with self.assertRaises(BootIdentityUnavailable):
                store.record_snapshot(agent_id='agent', identity=identity, sessions=(),
                                      complete=True, observed_at=1, order_token=100)

    def test_unavailable_boot_identity_rejects_all_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('codelight_core.boot_epoch.boot_identity', side_effect=BootIdentityUnavailable):
                store = LifecycleEvidenceStore(str(Path(directory) / 'authority.sqlite3'))
                replay = store.replay_inventory({'agent': frozenset()}, EvidenceOrder(100, 0, 'scan'))
            self.assertEqual(replay.stale_inventory_agents, frozenset({'agent'}))

    def test_legacy_database_and_markers_are_preserved_without_adoption(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = Path(directory) / 'authority.sqlite3'
            legacy.write_bytes(b'legacy history')
            markers = Path(f'{legacy}.taints')
            markers.mkdir()
            (markers / 'broken').write_bytes(b'old partial marker')
            store = LifecycleEvidenceStore(str(legacy))
            replay = store.replay_inventory({'agent': frozenset()}, EvidenceOrder(100, 0, 'scan'))
            self.assertEqual(replay.stale_inventory_agents, frozenset())
            self.assertEqual(legacy.read_bytes(), b'legacy history')
            self.assertEqual((markers / 'broken').read_bytes(), b'old partial marker')

    def test_missing_epoch_metadata_never_adopts_existing_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            persistence = BootPersistence(str(Path(directory) / 'authority.sqlite3'))
            path = Path(persistence.verified_path())
            path.write_bytes(b'old authority')
            (path.parent / 'boot-id').unlink()
            with self.assertRaises(BootIdentityUnavailable):
                persistence.verified_path()

    def test_late_old_boot_writer_cannot_mutate_current_epoch(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LifecycleEvidenceStore(str(Path(directory) / 'authority.sqlite3'))
            with patch('codelight_core.boot_epoch.boot_identity', return_value='22222222-2222-4222-8222-222222222222'):
                with self.assertRaises(BootIdentityUnavailable):
                    store.invalidate_agent('agent', 100)

    def test_previous_boot_future_database_and_taints_do_not_reject_inventory(self):
        # Given old-boot future evidence in both durable channels.
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'authority.sqlite3')
            with patch('codelight_core.boot_epoch.boot_identity', return_value='11111111-1111-4111-8111-111111111111'):
                identity = ProcessIdentity(123, 1, 'generation', '/bin/agent', '')
                old = LifecycleEvidenceStore(path)
                old.record_snapshot(agent_id='agent', identity=identity, sessions=(),
                                    complete=True, observed_at=1, order_token=1601000000000000)
                old.invalidate_agent('agent', 1601000000000001)
            # When exact inventory is collected after a reboot resetting monotonic time.
            with patch('codelight_core.boot_epoch.boot_identity', return_value='22222222-2222-4222-8222-222222222222'):
                current = LifecycleEvidenceStore(path)
                replay = current.replay_inventory({'agent': frozenset({identity})},
                                                  EvidenceOrder(132000000000000, 0, 'inventory'))
            # Then old claims neither prove idle nor invalidate the fresh inventory.
            self.assertEqual(replay.stale_inventory_agents, frozenset())
            self.assertFalse(replay.providers[0].complete)

    def test_same_boot_restart_preserves_unresolved_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'authority.sqlite3')
            identity = ProcessIdentity(123, 1, 'generation', '/bin/agent', '')
            first = LifecycleEvidenceStore(path)
            first.record_snapshot(agent_id='agent', identity=identity, sessions=(),
                                  complete=True, observed_at=1, order_token=100)
            first.invalidate_agent('agent', 200)
            replay = LifecycleEvidenceStore(path).replay({'agent': frozenset({identity})})
            self.assertFalse(replay[0].complete)


if __name__ == '__main__':
    unittest.main()
