import json
from pathlib import Path
import tempfile
import time
import unittest
import uuid

from codelight_core.lifecycle_evidence_taint import GenerationTaintStore


class TransportFailureTaintTests(unittest.TestCase):
    def test_unordered_failure_receives_one_stable_authority_clock_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure.taint"
            path.write_text(json.dumps({
                "kind": "agent", "agent_id": "opencode", "authority_rank": 1,
                "operation_id": f"transport-failed-{uuid.uuid4()}", "order_token": None,
            }))
            before = time.monotonic_ns()
            first, malformed = GenerationTaintStore(directory).attempts()
            second, malformed_after_restart = GenerationTaintStore(directory).attempts()
            self.assertFalse(malformed or malformed_after_restart)
            self.assertEqual(len(first), 1)
            self.assertGreaterEqual(first[0].order.token, before)
            self.assertEqual(second, first)

    def test_invalid_failure_nonce_remains_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure.taint"
            path.write_text(json.dumps({
                "kind": "agent", "agent_id": "opencode", "authority_rank": 1,
                "operation_id": "transport-failed-../escape", "order_token": None,
            }))
            operations, malformed = GenerationTaintStore(directory).attempts()
            self.assertEqual(operations, ())
            self.assertTrue(malformed)
