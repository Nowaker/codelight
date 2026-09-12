from pathlib import Path
from contextlib import contextmanager
import json
import os
import tempfile
import time
import unittest
from unittest import mock

import codelight

from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_taint import GenerationTaintStore
from codelight_core.lifecycle_evidence_taint_io import InvalidTaintMarkerError, TaintDirectory
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.state import CodelightState


class TaintInventoryRescanTests(unittest.TestCase):
    def test_hard_error_seen_before_disappearance_survives_clean_retry(self):
        errors = (json.JSONDecodeError("invalid", "{", 0), InvalidTaintMarkerError(),
                  PermissionError(13, "denied"), OSError(5, "io"))
        for error in errors:
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                hard = Path(directory) / "a-hard.taint"
                gone = Path(directory) / "b-gone.taint"
                hard.touch()
                gone.touch()
                reader = TaintDirectory(directory)
                parse = reader._parse
                native_scandir = os.scandir

                @contextmanager
                def ordered_scan(path):
                    with native_scandir(path) as entries:
                        yield iter(sorted(entries, key=lambda entry: entry.name))

                def read_then_remove(path):
                    if path == str(hard):
                        raise error
                    hard.unlink()
                    gone.unlink()
                    return parse(path)

                with (mock.patch("codelight_core.lifecycle_evidence_taint_io.os.scandir", side_effect=ordered_scan),
                      mock.patch.object(reader, "_parse", side_effect=read_then_remove)):
                    self.assertEqual(reader.inventory(), ((), (), True))

    def test_pending_replacement_is_preserved_by_fresh_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gone.taint"
            path.touch()
            pending_path = Path(directory) / f".{('a' * 64)}.{('b' * 64)}-00000000000000000100-1-pending.taint.nonce.tmp"
            reader = TaintDirectory(directory)
            parse = reader._parse

            def replace_with_pending(filename):
                pending_path.touch()
                path.unlink()
                return parse(filename)

            with mock.patch.object(reader, "_parse", side_effect=replace_with_pending):
                operations, pending, malformed = reader.inventory()
            self.assertEqual(operations, ())
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0].path, str(pending_path))
            self.assertFalse(malformed)
            self.assertTrue(GenerationTaintStore(directory).attempts()[1])

    def test_pending_evidence_seen_before_disappearance_survives_clean_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / f".{('a' * 64)}.{('b' * 64)}-00000000000000000100-1-pending.taint.nonce.tmp"
            gone = Path(directory) / "gone.taint"
            pending_path.touch()
            gone.touch()
            reader = TaintDirectory(directory)
            parse = reader._parse
            native_scandir = os.scandir

            @contextmanager
            def ordered_scan(path):
                with native_scandir(path) as entries:
                    yield iter(sorted(entries, key=lambda entry: entry.name))

            def remove_both(path):
                pending_path.unlink()
                gone.unlink()
                return parse(path)

            with (mock.patch("codelight_core.lifecycle_evidence_taint_io.os.scandir", side_effect=ordered_scan),
                  mock.patch.object(reader, "_parse", side_effect=remove_both)):
                self.assertEqual(reader.inventory(), ((), (), True))

    def test_missing_directory_keeps_empty_inventory_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(TaintDirectory(str(Path(directory) / "missing")).inventory(), ((), (), False))

    def test_completed_scope_removed_after_listing_gets_a_fresh_clean_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            store = GenerationTaintStore(directory)
            identity = ProcessIdentity(100, 1, "generation", "opencode", "opencode")
            marker = store.mark("opencode", identity, "scope", EvidenceOrder(100, 0, "completed"))
            reader = TaintDirectory(directory)
            parse = reader._parse

            def writer_completes(path: str):
                store.clear_success(marker)
                return parse(path)

            with mock.patch.object(reader, "_parse", side_effect=writer_completes):
                self.assertEqual(reader.inventory(), ((), (), False))

    def test_second_unstable_scan_stays_unknown_without_unbounded_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            store = GenerationTaintStore(directory)
            store.mark_agent("opencode", EvidenceOrder(100, 1, "initial"))
            reader = TaintDirectory(directory)
            parse = reader._parse
            calls = 0

            def replace_each_marker(path: str):
                nonlocal calls
                calls += 1
                store.mark_agent("opencode", EvidenceOrder(100 + calls, 1, f"replacement-{calls}"))
                Path(path).unlink()
                return parse(path)

            with (mock.patch.object(reader, "_parse", side_effect=replace_each_marker),
                  mock.patch("codelight_core.lifecycle_evidence_taint_io.os.scandir", wraps=os.scandir) as scans):
                self.assertEqual(reader.inventory(), ((), (), True))
                self.assertEqual(scans.call_count, 2)
            self.assertEqual(calls, 2)
            remaining, malformed = store.attempts()
            self.assertFalse(malformed)
            self.assertEqual(len(remaining), 1)

    def test_permission_error_is_not_retried_or_hidden(self):
        with tempfile.TemporaryDirectory() as directory:
            store = GenerationTaintStore(directory)
            store.mark_agent("opencode", EvidenceOrder(100, 1, "failure"))
            reader = TaintDirectory(directory)
            with mock.patch.object(reader, "_parse", side_effect=PermissionError(13, "denied")) as parse:
                self.assertEqual(reader.inventory(), ((), (), True))
                parse.assert_called_once()

    def test_genuine_malformed_inventory_publishes_specific_failure_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LifecycleEvidenceStore(str(Path(directory) / "evidence.sqlite3"))
            identity = ProcessIdentity(100, 1, "generation", "opencode", "opencode")
            store.record_snapshot(agent_id="opencode", identity=identity, sessions=(),
                                  complete=True, observed_at=time.time(), order_token=time.monotonic_ns())
            taints = Path(store._path + ".taints")
            taints.mkdir(exist_ok=True)
            (taints / "malformed.taint").write_text("{")
            state = CodelightState(default_agent_id="opencode", agent_registry={},
                                   idle_window=60, idle_window_waiting=60)
            state.set_enabled_agents({"opencode"})
            with (mock.patch.object(codelight, "_state", state),
                  mock.patch.object(codelight, "_lifecycle_evidence_store", store),
                  mock.patch.object(codelight._agent_process_probe, "identities",
                                    return_value={"opencode": frozenset({identity})})):
                codelight._restore_lifecycle_evidence({"opencode"})
            snapshot = state.power_authority_snapshot()
            self.assertEqual(snapshot["state"], "unknown")
            self.assertIn("taint-inventory-incomplete", snapshot["providers"]["opencode"].get("reasons", []))
