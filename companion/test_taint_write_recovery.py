import multiprocessing
import os
import signal
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Literal, cast
from unittest import mock

from codelight_core.evidence_order import UNKNOWN_RANK, evidence_order
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore, LifecycleReplay


def test_identity() -> ProcessIdentity:
    return ProcessIdentity(
        pid=100,
        ppid=1,
        started_at="darwin:1788076913:123456",
        executable="/opt/homebrew/bin/codex",
        command="/opt/homebrew/bin/codex",
    )


def interrupt_before_taint_publication(
    path: str,
    kind: Literal["scan", "scope"],
    ready: Connection,
) -> None:
    store = LifecycleEvidenceStore(path)
    create_temporary = tempfile.mkstemp

    def stop_after_create(
        suffix: str | None = None,
        prefix: str | None = None,
        dir: str | None = None,
        text: bool = False,
    ) -> tuple[int, str]:
        created = create_temporary(suffix, prefix, dir, text)
        ready.send(created[1])
        ready.close()
        os.kill(os.getpid(), signal.SIGSTOP)
        return created

    with mock.patch.object(tempfile, "mkstemp", side_effect=stop_after_create):
        match kind:
            case "scan":
                store.invalidate_inventory_scan_failure("codex", 200, "scan-crash")
            case "scope":
                store.record(
                    agent_id="codex",
                    identity=test_identity(),
                    session_id="session-1",
                    state="working",
                    observed_at=time.time(),
                    hook_event="UserPromptSubmit",
                    order_token=200,
                    operation_id="scope-crash",
                )


@dataclass(frozen=True)
class TaintFixture:
    path: str
    store: LifecycleEvidenceStore
    identity: ProcessIdentity

    def record_idle(self, order_token: int) -> None:
        self.store.record_snapshot(
            agent_id="codex",
            identity=self.identity,
            sessions=(),
            complete=True,
            observed_at=time.time(),
            order_token=order_token,
            operation_id="known-idle",
        )

    def replay_inventory(self, order_token: int) -> LifecycleReplay:
        return self.store.replay_inventory(
            {"codex": frozenset({self.identity})},
            evidence_order(order_token, UNKNOWN_RANK, "successful-inventory"),
            now_order_token=order_token,
        )

    def operation_ids(self) -> tuple[str, ...]:
        with closing(sqlite3.connect(self.store._path)) as connection:
            rows = cast(
                list[tuple[object, ...]],
                connection.execute(
                    "SELECT operation_id FROM agent_invalidations ORDER BY operation_id"
                ).fetchall(),
            )
        operation_ids: list[str] = []
        for row in rows:
            if len(row) != 1 or not isinstance(row[0], str):
                raise AssertionError("invalid agent invalidation row")
            operation_ids.append(row[0])
        return tuple(operation_ids)


def taint_fixture(tmp: str) -> TaintFixture:
    path = os.path.join(tmp, "evidence.sqlite3")
    return TaintFixture(path, LifecycleEvidenceStore(path), test_identity())


class TaintWriteRecoveryTests(unittest.TestCase):
    def interrupted_write(
        self,
        fixture: TaintFixture,
        kind: Literal["scan", "scope"],
    ) -> str:
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        process = context.Process(
            target=interrupt_before_taint_publication,
            args=(fixture.path, kind, send),
        )
        process.start()
        send.close()
        try:
            if not receive.poll(10):
                self.fail("child did not create the pending taint marker")
            received_path = cast(object, receive.recv())
            if not isinstance(received_path, str):
                self.fail("child returned an invalid pending taint path")
            pending_path = received_path
        finally:
            if process.is_alive():
                process.kill()
            process.join(10)
            receive.close()
        self.assertFalse(process.is_alive())
        return pending_path

    def test_interrupted_scope_write_fails_closed_until_complete_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = taint_fixture(tmp)
            fixture.record_idle(100)
            pending_path = self.interrupted_write(fixture, "scope")

            interrupted_replay = fixture.replay_inventory(300)

            self.assertFalse(interrupted_replay.providers[0].complete)
            self.assertTrue(os.path.exists(pending_path))

            with mock.patch.object(
                os,
                "fsync",
                side_effect=OSError("recovery sidecar unavailable"),
            ):
                fixture.store.record_snapshot(
                    agent_id="codex",
                    identity=fixture.identity,
                    sessions=(),
                    complete=True,
                    observed_at=time.time(),
                    order_token=400,
                    operation_id="recovered-idle",
                )
            recovered_replay = fixture.replay_inventory(500)

            self.assertTrue(recovered_replay.providers[0].complete)
            self.assertFalse(os.path.exists(pending_path))

    def test_interrupted_scan_guard_is_conservative_then_inventory_recovers(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = taint_fixture(tmp)
            fixture.record_idle(100)
            pending_path = self.interrupted_write(fixture, "scan")

            interrupted_replay = fixture.store.replay(
                {"codex": frozenset({fixture.identity})},
                now_order_token=250,
            )[0]
            recovered_replay = fixture.replay_inventory(300)

            self.assertFalse(interrupted_replay.complete)
            self.assertTrue(recovered_replay.providers[0].complete)
            self.assertFalse(os.path.exists(pending_path))

    def test_exact_absence_clears_interrupted_scope_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = taint_fixture(tmp)
            fixture.record_idle(100)
            pending_path = self.interrupted_write(fixture, "scope")

            fixture.store.clear_agent_invalidation(
                "codex", 300, "exact-absence"
            )

            self.assertFalse(os.path.exists(pending_path))

    def test_partial_scan_write_recovers_through_sqlite_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = taint_fixture(tmp)
            fixture.record_idle(100)
            write = os.write
            writes = 0

            def fail_after_partial_write(descriptor: int, data: bytes) -> int:
                nonlocal writes
                if writes == 0:
                    writes += 1
                    return write(descriptor, data[: max(1, len(data) // 2)])
                raise OSError("marker write interrupted")

            with mock.patch.object(os, "write", side_effect=fail_after_partial_write):
                fixture.store.invalidate_inventory_scan_failure(
                    "codex", 200, "partial-scan"
                )

            first_replay = fixture.replay_inventory(300)
            second_replay = fixture.replay_inventory(400)
            taint_names = tuple(
                entry.name
                for entry in os.scandir(f"{fixture.store._path}.taints")
                if entry.name.endswith((".taint", ".tmp"))
            )

            self.assertTrue(first_replay.providers[0].complete)
            self.assertTrue(second_replay.providers[0].complete)
            self.assertEqual(fixture.operation_ids(), ())
            self.assertEqual(taint_names, ())

    def test_unrelated_malformed_taint_remains_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = taint_fixture(tmp)
            fixture.record_idle(100)
            taint_directory = f"{fixture.store._path}.taints"
            os.makedirs(taint_directory, mode=0o700, exist_ok=True)
            malformed_path = os.path.join(taint_directory, "legacy.taint")
            with open(malformed_path, "w", encoding="utf-8") as marker:
                _ = marker.write('{"kind":"agent"')

            replay = fixture.replay_inventory(300)

            self.assertFalse(replay.providers[0].complete)
            self.assertTrue(os.path.exists(malformed_path))


if __name__ == "__main__":
    _ = unittest.main()
