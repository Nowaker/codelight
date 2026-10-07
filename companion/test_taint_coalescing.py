import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from unittest import mock

from codelight_core.evidence_order import EvidenceOrder, inventory_scan_failure_order
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.lifecycle_evidence_inventory import collect_taint_invalidations
from codelight_core.lifecycle_evidence_taint import GenerationTaintStore
from codelight_core.lifecycle_evidence_taint_io import (
    SCOPE_CONTAINER,
    SCOPE_LAYOUT_MARKER,
    TRANSPORT_FAILURE_MARKER_SUFFIX,
    TaintDirectory,
    agent_marker_prefix,
)


def canonical_failure(directory: str, agent_id: str = "opencode") -> Path:
    """Write the coalesced marker exactly as codelight_failure.ts does."""
    path = Path(directory) / f"{agent_marker_prefix(agent_id)}{TRANSPORT_FAILURE_MARKER_SUFFIX}"
    path.write_text(json.dumps({
        "kind": "agent", "agent_id": agent_id, "order_token": None,
        "authority_rank": 1, "operation_id": f"transport-failed-{uuid.uuid4()}",
    }))
    return path


def legacy_failure(directory: str, agent_id: str = "opencode") -> Path:
    operation = f"transport-failed-{uuid.uuid4()}"
    path = Path(directory) / f"{agent_marker_prefix(agent_id)}-{'0' * 20}-1-{operation}.taint"
    path.write_text(json.dumps({
        "kind": "agent", "agent_id": agent_id, "order_token": None,
        "authority_rank": 1, "operation_id": operation,
    }))
    return path


def marker_files(directory: str) -> list[str]:
    return sorted(
        os.path.relpath(os.path.join(root, name), directory)
        for root, _directories, names in os.walk(directory)
        for name in names
    )


class TransportFailureCoalescingTests(unittest.TestCase):
    def test_canonical_failure_is_claimed_and_promoted_after_the_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = canonical_failure(directory)
            before = time.monotonic_ns()
            operations, malformed = GenerationTaintStore(directory).attempts()

            self.assertFalse(malformed)
            self.assertEqual(len(operations), 1)
            self.assertIsNone(operations[0].identity)
            self.assertGreater(operations[0].order.token, before)
            self.assertFalse(marker.exists())
            self.assertEqual(marker_files(directory), [os.path.basename(operations[0].path)])

    def test_failure_after_the_claim_raises_a_newer_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            canonical_failure(directory)
            reader = TaintDirectory(directory)
            claim = reader._claim

            def failure_lands_after_claim(path: str) -> str:
                claimed = claim(path)
                canonical_failure(directory)
                return claimed

            with mock.patch.object(reader, "_claim", side_effect=failure_lands_after_claim):
                first, _pending, malformed = reader.inventory()
            self.assertFalse(malformed)
            self.assertTrue(any(name.endswith(TRANSPORT_FAILURE_MARKER_SUFFIX) for name in os.listdir(directory)))

            second, malformed = GenerationTaintStore(directory).attempts()
            self.assertFalse(malformed)
            self.assertEqual(len(second), 1)
            self.assertGreater(second[0].order, first[0].order)

    def test_a_claim_lost_to_a_competing_reader_rescans(self):
        with tempfile.TemporaryDirectory() as directory:
            canonical_failure(directory)
            reader = TaintDirectory(directory)
            claim = reader._claim
            competing = []

            def competing_reader_claims_first(path: str) -> str:
                if not competing:
                    competing.extend(GenerationTaintStore(directory).attempts()[0])
                return claim(path)

            with mock.patch.object(reader, "_claim", side_effect=competing_reader_claims_first):
                operations, pending, malformed = reader.inventory()

            self.assertEqual(operations, tuple(competing))
            self.assertEqual(pending, ())
            self.assertFalse(malformed)

    def test_interrupted_claim_is_promoted_by_the_next_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = canonical_failure(directory)
            claimed = TaintDirectory._claim(str(marker))

            operations, malformed = GenerationTaintStore(directory).attempts()

            self.assertFalse(malformed)
            self.assertEqual(len(operations), 1)
            self.assertFalse(os.path.exists(claimed))

    def test_legacy_backlog_costs_one_marker_write_per_agent(self):
        with tempfile.TemporaryDirectory() as directory:
            for _ in range(50):
                legacy_failure(directory)
            legacy_failure(directory, "codex")
            reader = TaintDirectory(directory)

            with mock.patch.object(reader, "write", wraps=reader.write) as write:
                operations, _pending, malformed = reader.inventory()

            self.assertFalse(malformed)
            self.assertEqual(write.call_count, 2)
            self.assertEqual(sorted(operation.agent_id for operation in operations), ["codex", "opencode"])
            self.assertEqual(len(marker_files(directory)), 2)


class DominatedAgentMarkerTests(unittest.TestCase):
    def test_full_inventory_keeps_only_the_newest_marker_per_cleanup_family(self):
        with tempfile.TemporaryDirectory() as directory:
            store = GenerationTaintStore(directory)
            identity = ProcessIdentity(100, 1, "generation", "opencode", "opencode")
            for token in (10, 30, 20):
                store.mark_agent("opencode", EvidenceOrder(token, 1, f"failed-{token}"))
            for token in (5, 25):
                store.mark_agent("opencode", inventory_scan_failure_order(token, f"scan-{token}"))
            store.mark_agent("codex", EvidenceOrder(15, 1, "codex"))
            store.mark("opencode", identity, "scope", EvidenceOrder(1, 0, "scope-1"))
            store.mark("opencode", identity, "scope", EvidenceOrder(2, 0, "scope-2"))
            unpruned = TaintDirectory(directory)
            with mock.patch(
                "codelight_core.lifecycle_evidence_taint_io.dominated_agent_markers",
                return_value=[],
            ):
                before = collect_taint_invalidations(unpruned.inventory()[0])

            operations, malformed = store.attempts()

            self.assertFalse(malformed)
            self.assertEqual(collect_taint_invalidations(operations), before)
            self.assertEqual(
                sorted(operation.order.token for operation in operations if operation.identity is None),
                [15, 25, 30],
            )
            self.assertEqual(len([operation for operation in operations if operation.identity]), 2)
            self.assertEqual(store.attempts(), (operations, False))

    def test_inventory_failure_cleanup_still_sees_its_own_family(self):
        with tempfile.TemporaryDirectory() as directory:
            store = GenerationTaintStore(directory)
            store.mark_agent("opencode", inventory_scan_failure_order(5, "scan"))
            store.mark_agent("opencode", EvidenceOrder(50, 1, "transport"))
            store.attempts()

            store.clear_inventory_scan_failures_before("opencode", EvidenceOrder(10, 1, "inventory"))

            operations, malformed = store.attempts()
            self.assertFalse(malformed)
            self.assertEqual([operation.order.token for operation in operations], [50])


class ScopeLayoutTests(unittest.TestCase):
    identity = ProcessIdentity(100, 1, "generation", "opencode", "opencode")

    def test_scope_markers_live_in_their_own_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            store = GenerationTaintStore(directory)
            operation = store.mark("opencode", self.identity, "scope", EvidenceOrder(1, 0, "one"))

            self.assertEqual(
                Path(operation.path).parent.parent,
                Path(directory) / SCOPE_CONTAINER,
            )
            operations, malformed = store.attempts()
            self.assertFalse(malformed)
            self.assertEqual([item.path for item in operations], [operation.path])

    def test_scope_cleanup_lists_only_its_scope_once_the_layout_is_migrated(self):
        with tempfile.TemporaryDirectory() as directory:
            store = GenerationTaintStore(directory)
            for index in range(5):
                legacy_failure(directory)
                store.mark("opencode", self.identity, f"other-{index}", EvidenceOrder(index, 0, str(index)))
            own = store.mark("opencode", self.identity, "own", EvidenceOrder(9, 0, "own"))
            Path(directory, SCOPE_LAYOUT_MARKER).touch()

            with mock.patch(
                "codelight_core.lifecycle_evidence_taint_io.os.scandir", wraps=os.scandir,
            ) as scans:
                store.clear_scope_through("opencode", self.identity, "own", EvidenceOrder(10, 0, "done"))

            self.assertEqual(
                [call.args[0] for call in scans.call_args_list],
                [os.path.dirname(own.path)],
            )
            self.assertFalse(os.path.exists(own.path))

    def test_scope_cleanup_still_clears_legacy_top_level_markers_before_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            store = GenerationTaintStore(directory)
            prefix = store._prefix("opencode", self.identity, "own")
            legacy = Path(directory) / f"{prefix}-{1:020d}-0-legacy.taint"
            legacy.write_text(json.dumps({
                "kind": "scope", "agent_id": "opencode", "pid": 100, "ppid": 1,
                "generation": "generation", "executable": "opencode", "scope_id": "own",
                "order_token": 1, "authority_rank": 0, "operation_id": "legacy",
            }))
            current = store.mark("opencode", self.identity, "own", EvidenceOrder(2, 0, "current"))

            store.clear_scope_through("opencode", self.identity, "own", EvidenceOrder(3, 0, "done"))

            self.assertFalse(legacy.exists())
            self.assertFalse(os.path.exists(current.path))

    def test_pending_scope_write_keeps_the_inventory_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            store = GenerationTaintStore(directory)
            operation = store.mark("opencode", self.identity, "scope", EvidenceOrder(1, 0, "one"))
            prefix = os.path.basename(os.path.dirname(operation.path))
            pending = Path(os.path.dirname(operation.path)) / (
                f".{agent_marker_prefix('opencode')}.{prefix}-{2:020d}-0-two.taint.nonce.tmp"
            )
            pending.touch()

            self.assertEqual(store.attempts(), ((), True))
            store.clear_scope_through("opencode", self.identity, "scope", EvidenceOrder(3, 0, "done"))
            self.assertEqual(store.attempts(), ((), False))

    def test_unexpected_entry_in_the_scope_container_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, SCOPE_CONTAINER).mkdir()
            Path(directory, SCOPE_CONTAINER, "stray").touch()

            self.assertEqual(GenerationTaintStore(directory).attempts(), ((), True))


class CoalescedReplaySemanticsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = LifecycleEvidenceStore(os.path.join(temporary.name, "evidence.sqlite3"))
        epoch = self.store.boot_id
        assert epoch is not None
        self.first = ProcessIdentity(100, 1, "generation:a", "/bin/opencode", "opencode", epoch)
        self.second = ProcessIdentity(200, 1, "generation:b", "/bin/opencode", "opencode", epoch)
        self.live = {"opencode": frozenset({self.first, self.second})}
        for identity in (self.first, self.second):
            self.snapshot(identity)
        self.taints = self.store._path + ".taints"

    def snapshot(self, identity: ProcessIdentity) -> None:
        self.store.record_snapshot(agent_id="opencode", identity=identity, sessions=(), complete=True,
                                   observed_at=time.time(), order_token=time.monotonic_ns())

    def complete(self) -> list[bool]:
        return [provider.complete for provider in self.store.replay(self.live)]

    def test_repeated_failures_are_one_barrier_that_every_generation_must_pass(self):
        self.assertEqual(self.complete(), [True, True])
        for _ in range(20):
            canonical_failure(self.taints)
        self.assertEqual(len(os.listdir(self.taints)), 2)

        self.assertEqual(self.complete(), [False, False])
        self.snapshot(self.first)
        self.assertEqual(self.complete(), [False, False])
        self.snapshot(self.second)
        self.assertEqual(self.complete(), [True, True])

    def test_failure_after_recovery_taints_again(self):
        canonical_failure(self.taints)
        self.complete()
        self.snapshot(self.first)
        self.snapshot(self.second)
        self.assertEqual(self.complete(), [True, True])

        canonical_failure(self.taints)

        self.assertEqual(self.complete(), [False, False])


if __name__ == "__main__":
    unittest.main()
