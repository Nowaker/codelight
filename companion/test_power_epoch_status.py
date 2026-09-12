import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from codelight_core.power_status_file import PowerStatusPublisher, read_power_status


class PowerEpochStatusTests(unittest.TestCase):
    def test_status_reader_preserves_safe_scope_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'status.json')
            scope = {'agentId': 'agent', 'scope': 'scope-hash', 'generation': 'generation-hash',
                     'orderToken': 100, 'snapshotOrderToken': 90, 'leaseDeadlineNs': 150,
                     'replayed': True, 'reason': 'scope-incomplete-or-invalidated'}
            PowerStatusPublisher(path).publish({
                'state': 'unknown', 'reason': 'stale-session-evidence',
                'providers': {'agent': {'state': 'unknown', 'activeSessions': 0,
                                        'reasons': ['scope-evidence-incomplete']}},
                'scopes': [scope],
            }, observed_at=100)
            result = read_power_status(path, now=101)
            self.assertEqual(result['scopes'], [scope])
            self.assertEqual(result['providers']['agent']['reasons'], ['scope-evidence-incomplete'])

    def test_status_from_previous_boot_is_unknown_despite_fresh_wall_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'status.json')
            publisher = PowerStatusPublisher(path)
            publisher.publish({'state': 'idle', 'reason': 'all-sessions-complete',
                               'providers': {'agent': {'state': 'idle', 'activeSessions': 0}}},
                              observed_at=100)
            with patch('codelight_core.power_status_file.boot_identity', return_value='new-boot'):
                result = read_power_status(path, now=101)
            self.assertEqual(result['state'], 'unknown')
            self.assertEqual(result['reason'], 'status-boot-mismatch')


if __name__ == '__main__':
    unittest.main()
