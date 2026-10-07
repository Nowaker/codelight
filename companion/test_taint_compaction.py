import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_compaction import compact_taints, count_entries
from codelight_core.lifecycle_evidence_inventory import collect_taint_invalidations
from codelight_core.lifecycle_evidence_taint import GenerationTaintStore
from codelight_core.lifecycle_evidence_taint_io import (
    SCOPE_CONTAINER,
    SCOPE_LAYOUT_MARKER,
    agent_marker_prefix,
)
from test_taint_coalescing import legacy_failure

LIVE = ProcessIdentity(100, 1, "generation:live", "opencode", "opencode")
DEAD = ProcessIdentity(200, 1, "generation:dead", "opencode", "opencode")


def alive(pid: int, generation: str) -> bool:
    return (pid, generation) == (LIVE.pid, LIVE.started_at)


def legacy_scope_marker(directory: str, identity: ProcessIdentity, scope: str, token: int) -> Path:
    prefix = GenerationTaintStore._prefix("opencode", identity, scope)
    path = Path(directory) / f"{prefix}-{token:020d}-0-op{token}.taint"
    path.write_text(json.dumps({
        "kind": "scope", "agent_id": "opencode", "pid": identity.pid, "ppid": identity.ppid,
        "generation": identity.started_at, "executable": identity.executable, "scope_id": scope,
        "order_token": token, "authority_rank": 0, "operation_id": f"op{token}",
    }))
    return path


def pending_write(directory: str, marker_prefix: str, token: int, content: str) -> Path:
    path = Path(directory) / (
        f".{agent_marker_prefix('opencode')}.{marker_prefix}-{token:020d}-0-op{token}.taint.nonce.tmp"
    )
    path.write_text(content)
    old = time.time() - 600
    os.utime(path, (old, old))
    return path


def age(directory: str) -> None:
    old = time.time() - 600
    for root, _directories, names in os.walk(directory):
        for name in names:
            os.utime(os.path.join(root, name), (old, old))


class CompactionTests(unittest.TestCase):
    def compact(self, directory: str, **options):
        return compact_taints(directory, ("opencode", "codex"), generation_alive=alive, **options)

    def test_preserves_invalidations_and_migrates_to_the_scope_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            for _ in range(30):
                legacy_failure(directory)
            GenerationTaintStore(directory).mark_agent("codex", EvidenceOrder(7, 1, "codex"))
            for token in (1, 2):
                legacy_scope_marker(directory, LIVE, "live-scope", token)
                legacy_scope_marker(directory, DEAD, "dead-scope", token)
            age(directory)
            before = time.monotonic_ns()

            result = self.compact(directory)

            self.assertTrue(result["layout"])
            self.assertEqual(result["actions"]["migrated-scope-marker"], 4)
            operations, malformed = GenerationTaintStore(directory).attempts()
            self.assertFalse(malformed)
            invalidations = collect_taint_invalidations(operations)
            self.assertEqual(invalidations.agents["codex"].token, 7)
            self.assertGreater(invalidations.agents["opencode"].token, before)
            self.assertEqual(len(invalidations.scopes), 2)
            self.assertEqual(result["after"].get("markers-top-level"), 2)
            self.assertTrue(Path(directory, SCOPE_LAYOUT_MARKER).exists())

    def test_dead_generation_evidence_is_dropped_only_on_request(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy_scope_marker(directory, LIVE, "live-scope", 1)
            dead = legacy_scope_marker(directory, DEAD, "dead-scope", 1)
            dead_prefix = dead.name[:64]
            pending_write(directory, dead_prefix, 2, '{"kind":"sco')
            age(directory)

            self.compact(directory, drop_dead_generations=True)

            operations, malformed = GenerationTaintStore(directory).attempts()
            self.assertFalse(malformed)
            self.assertEqual([operation.identity.pid for operation in operations if operation.identity], [100])

    def test_complete_pending_write_is_finished_and_partial_unattributed_one_still_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            live = legacy_scope_marker(directory, LIVE, "live-scope", 1)
            complete = live.read_text().replace('"order_token": 1', '"order_token": 3').replace("op1", "op3")
            pending_write(directory, live.name[:64], 3, complete)
            pending_write(directory, "e" * 64, 4, '{"kind":')

            result = self.compact(directory, drop_dead_generations=True)

            self.assertEqual(result["actions"]["finished-pending-scope"], 1)
            self.assertEqual(result["actions"]["kept-partial-pending-scope"], 1)
            self.assertEqual(GenerationTaintStore(directory).attempts(), ((), True))
            store = GenerationTaintStore(directory)
            store._files.unlink(next(
                os.path.join(root, name)
                for root, _directories, names in os.walk(directory)
                for name in names if name.endswith(".tmp")
            ))
            tokens = sorted(operation.order.token for operation in store.attempts()[0])
            self.assertEqual(tokens, [1, 3])

    def test_partial_agent_write_becomes_a_fresh_agent_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = agent_marker_prefix("opencode")
            path = Path(directory) / f".{prefix}.{prefix}-{0:020d}-1-transport-failed.taint.nonce.tmp"
            path.write_text('{"kind":"ag')
            old = time.time() - 600
            os.utime(path, (old, old))
            before = time.monotonic_ns()

            self.compact(directory)

            operations, malformed = GenerationTaintStore(directory).attempts()
            self.assertFalse(malformed)
            self.assertEqual(len(operations), 1)
            self.assertIsNone(operations[0].identity)
            self.assertGreater(operations[0].order.token, before)

    def test_recent_pending_writes_are_left_to_their_writers(self):
        with tempfile.TemporaryDirectory() as directory:
            pending = pending_write(directory, "e" * 64, 4, "{")
            os.utime(pending)

            result = self.compact(directory, drop_dead_generations=True)

            self.assertTrue(pending.exists())
            self.assertFalse(result["layout"])

    def test_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            for _ in range(5):
                legacy_failure(directory)
            legacy_scope_marker(directory, LIVE, "live-scope", 1)
            age(directory)
            self.compact(directory)
            first = GenerationTaintStore(directory).attempts()

            again = self.compact(directory)

            self.assertEqual(GenerationTaintStore(directory).attempts(), first)
            self.assertEqual(again["before"], again["after"])
            self.assertNotIn("migrated-scope-marker", again["actions"])
            self.assertEqual(count_entries(directory).get("markers-scoped"), 1)
            self.assertTrue(Path(directory, SCOPE_CONTAINER).is_dir())


if __name__ == "__main__":
    unittest.main()
