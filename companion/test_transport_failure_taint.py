import json
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from unittest import mock

from codelight_core.lifecycle_evidence_taint import GenerationTaintStore
from codelight_core.lifecycle_evidence_taint_io import TaintDirectory


class TransportFailureTaintTests(unittest.TestCase):
    def test_promotion_between_listing_and_reading_cannot_report_empty_clean_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure.taint"
            path.write_text(json.dumps({
                "kind": "agent", "agent_id": "opencode", "authority_rank": 1,
                "operation_id": f"transport-failed-{uuid.uuid4()}", "order_token": None,
            }))
            first_reader = TaintDirectory(directory)
            parse = first_reader._parse

            def competing_promotion(filename: str):
                promoted, malformed = GenerationTaintStore(directory).attempts()
                self.assertFalse(malformed)
                self.assertEqual(len(promoted), 1)
                return parse(filename)

            with mock.patch.object(first_reader, "_parse", side_effect=competing_promotion):
                operations, pending, malformed = first_reader.inventory()

            self.assertEqual((operations, pending), ((), ()))
            self.assertTrue(malformed)

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
