import tempfile
import unittest
from pathlib import Path

from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore


class RecoveryFloorTests(unittest.TestCase):
    def test_recovered_global_uncertainty_does_not_return_when_reporter_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'evidence.sqlite3')
            store = LifecycleEvidenceStore(path)
            identity = ProcessIdentity(1, 0, 'first', '/agent', '')
            store.invalidate_agent('agent', 100)
            store.record_snapshot(agent_id='agent', identity=identity, sessions=(),
                                  complete=True, observed_at=1, order_token=200)
            store.replay_inventory({'agent': frozenset({identity})}, EvidenceOrder(300, 0, 'scan'), now_order_token=300)
            # Given a delayed failure already covered by the exact recovery proof.
            store.invalidate_agent('agent', 190)
            restarted = LifecycleEvidenceStore(path)
            replacement = ProcessIdentity(2, 0, 'second', '/agent', '')
            restarted.record_snapshot(agent_id='agent', identity=replacement, sessions=(),
                                      complete=True, observed_at=1, order_token=160)
            replay = restarted.replay({'agent': frozenset({replacement})}, now_order_token=400)
            self.assertTrue(replay[0].complete)


if __name__ == '__main__':
    unittest.main()
