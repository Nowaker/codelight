import unittest

from codelight_core.power_authority import AuthoritySession, PowerAuthority


class PowerProjectionPurityTests(unittest.TestCase):
    def test_temporary_projection_unknown_does_not_latch_into_recorded_authority(self):
        authority = PowerAuthority()
        authority.set_enabled_agents({'agent'})
        authority.record_snapshot('agent', True)
        unknown = authority.snapshot((AuthoritySession('session', 'agent', 'unknown'),))
        settled = authority.snapshot(())
        self.assertEqual(unknown['state'], 'unknown')
        self.assertEqual(settled['state'], 'idle')


if __name__ == '__main__':
    unittest.main()
