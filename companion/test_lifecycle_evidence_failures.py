import os
import sqlite3
import stat
import tempfile
import threading
import unittest
from unittest import mock

from codelight_core.evidence_order import ACTIVE_RANK, evidence_order
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.lifecycle_evidence_invalidation import ScopeWrite
from codelight_core.power_authority import AuthoritySession


class LifecycleEvidenceFailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "evidence.sqlite3")
        self.store = LifecycleEvidenceStore(self.path)
        self.identity = ProcessIdentity(
            pid=100,
            ppid=1,
            started_at="Sun Aug 30 04:01:53 2026",
            executable="/opt/homebrew/bin/codex",
            command="/opt/homebrew/bin/codex",
        )

    def record(self, state, observed_at):
        self.store.record(
            agent_id="codex",
            identity=self.identity,
            session_id="session-1",
            state=state,
            observed_at=observed_at,
            hook_event="Stop" if state == "ended" else "UserPromptSubmit",
        )

    def replay(self):
        return self.store.replay({"codex": frozenset({self.identity})})

    def fail_next_write(self, state, observed_at):
        with (
            mock.patch.object(
                self.store,
                "_connect",
                side_effect=sqlite3.OperationalError("database is locked"),
            ),
            self.assertRaises(sqlite3.OperationalError),
        ):
            self.record(state, observed_at)

    def test_failed_working_write_invalidates_older_idle_evidence(self):
        self.record("ended", 100.0)

        self.fail_next_write("working", 200.0)

        replay = self.replay()
        self.assertFalse(replay[0].complete)
        self.assertEqual(replay[0].sessions, ())

    def test_failed_completion_write_invalidates_older_active_evidence(self):
        self.record("working", 100.0)

        self.fail_next_write("ended", 200.0)

        replay = self.replay()
        self.assertFalse(replay[0].complete)
        self.assertEqual(replay[0].sessions, ())

    def test_complete_snapshot_clears_failed_generation_taint(self):
        self.record("ended", 100.0)
        self.fail_next_write("working", 200.0)

        self.store.record_snapshot(
            agent_id="codex",
            identity=self.identity,
            sessions=(AuthoritySession("session-1", "codex", "working"),),
            complete=True,
            observed_at=300.0,
        )

        self.assertEqual(self.replay()[0].sessions[0].state, "working")

    def test_independent_event_does_not_clear_inflight_guard(self):
        self.record("ended", 50.0)
        self.store._invalidations.begin_scope_write(
            ScopeWrite(
                "codex",
                self.identity,
                "",
                evidence_order(100, ACTIVE_RANK, "event-a"),
            )
        )

        self.store.record(
            agent_id="codex",
            identity=self.identity,
            session_id="session-b",
            state="working",
            observed_at=101.0,
            order_token=101,
            operation_id="event-b-working",
            hook_event="UserPromptSubmit",
        )
        self.store.record(
            agent_id="codex",
            identity=self.identity,
            session_id="session-b",
            state="ended",
            observed_at=102.0,
            order_token=102,
            operation_id="event-b-ended",
            hook_event="Stop",
        )

        replay = self.replay()[0]
        self.assertFalse(replay.complete)
        self.assertEqual(replay.sessions, ())

    def test_database_guard_is_scoped_to_one_operation(self):
        self.record("ended", 50.0)
        with mock.patch.object(
            self.store._taints,
            "mark",
            side_effect=OSError("marker unavailable"),
        ):
            self.store._invalidations.begin_scope_write(
                ScopeWrite(
                    "codex",
                    self.identity,
                    "",
                    evidence_order(100, ACTIVE_RANK, "event-a"),
                )
            )
            self.store.record(
                agent_id="codex",
                identity=self.identity,
                session_id="session-b",
                state="working",
                observed_at=101.0,
                order_token=101,
                operation_id="event-b-working",
                hook_event="UserPromptSubmit",
            )
            self.store.record(
                agent_id="codex",
                identity=self.identity,
                session_id="session-b",
                state="ended",
                observed_at=102.0,
                order_token=102,
                operation_id="event-b-ended",
                hook_event="Stop",
            )

        replay = self.replay()[0]
        self.assertFalse(replay.complete)
        self.assertEqual(replay.sessions, ())

    def test_database_is_private_to_the_current_user(self):
        self.record("ended", 100.0)

        mode = stat.S_IMODE(os.stat(self.path).st_mode)

        self.assertEqual(mode, 0o600)

    def test_agent_taint_survives_resolved_event_until_exact_absence(self):
        self.record("ended", 100.0)

        self.store.invalidate_agent("codex", 200_000_000_000)

        replay = self.replay()
        self.assertFalse(replay[0].complete)
        self.assertEqual(replay[0].sessions, ())

        self.record("working", 300.0)
        self.assertFalse(self.replay()[0].complete)

        self.store.clear_agent_invalidation("codex", 400_000_000_000)
        self.assertEqual(self.replay()[0].sessions[0].state, "working")

    def test_every_live_generation_snapshot_recovers_older_agent_taint(self):
        second_identity = ProcessIdentity(
            pid=200,
            ppid=1,
            started_at="Sun Aug 30 04:02:53 2026",
            executable="/opt/homebrew/bin/codex",
            command="/opt/homebrew/bin/codex",
        )
        self.store.invalidate_agent("codex", 100)
        for token, identity in ((200, self.identity), (201, second_identity)):
            self.store.record_snapshot(
                agent_id="codex",
                identity=identity,
                sessions=(),
                complete=True,
                observed_at=float(token),
                order_token=token,
            )

        replay = self.store.replay(
            {"codex": frozenset({self.identity, second_identity})},
            now_order_token=300,
        )

        self.assertTrue(all(provider.complete for provider in replay))

    def test_one_live_generation_without_snapshot_keeps_agent_tainted(self):
        second_identity = ProcessIdentity(
            pid=200,
            ppid=1,
            started_at="Sun Aug 30 04:02:53 2026",
            executable="/opt/homebrew/bin/codex",
            command="/opt/homebrew/bin/codex",
        )
        self.store.invalidate_agent("codex", 100)
        self.store.record_snapshot(
            agent_id="codex",
            identity=self.identity,
            sessions=(),
            complete=True,
            observed_at=200.0,
            order_token=200,
        )

        replay = self.store.replay(
            {"codex": frozenset({self.identity, second_identity})},
            now_order_token=300,
        )

        self.assertTrue(all(not provider.complete for provider in replay))

    def test_database_fallback_is_used_when_sidecar_marker_creation_fails(self):
        self.record("ended", 100.0)

        with mock.patch.object(
            self.store._taints,
            "mark",
            side_effect=OSError("marker unavailable"),
        ):
            self.record("working", 200.0)

        replay = self.replay()[0]
        self.assertTrue(replay.complete)
        self.assertEqual(replay.sessions[0].state, "working")

    def test_database_fallback_remains_invalid_when_followup_write_fails(self):
        self.record("ended", 100.0)
        original_connect = self.store._connect
        connect_calls = 0

        def connect():
            nonlocal connect_calls
            connect_calls += 1
            if connect_calls == 2:
                raise sqlite3.OperationalError("database is locked")
            return original_connect()

        with (
            mock.patch.object(
                self.store._taints,
                "mark",
                side_effect=OSError("marker unavailable"),
            ),
            mock.patch.object(self.store, "_connect", side_effect=connect),
            self.assertRaises(sqlite3.OperationalError),
        ):
            self.record("working", 200.0)

        replay = self.replay()[0]
        self.assertFalse(replay.complete)
        self.assertEqual(replay.sessions, ())

    def test_sidecar_only_failed_scope_replays_explicit_unknown(self):
        self.store.record_snapshot(
            agent_id="codex",
            identity=self.identity,
            scope_id="/repo-idle",
            sessions=(),
            complete=True,
            observed_at=100.0,
        )

        with (
            mock.patch.object(
                self.store,
                "_connect",
                side_effect=sqlite3.OperationalError("database is locked"),
            ),
            self.assertRaises(sqlite3.OperationalError),
        ):
            self.store.record(
                agent_id="codex",
                identity=self.identity,
                scope_id="/repo-working",
                session_id="working-session",
                state="working",
                observed_at=200.0,
                hook_event="UserPromptSubmit",
            )

        replay = self.replay()
        by_scope = {provider.scope_id: provider for provider in replay}
        self.assertTrue(by_scope["/repo-idle"].complete)
        self.assertFalse(by_scope["/repo-working"].complete)

    def test_replay_reads_provider_and_sessions_from_one_snapshot(self):
        journal_connection = self.store._connect()
        try:
            journal_connection.execute("PRAGMA journal_mode = WAL").fetchone()
        finally:
            journal_connection.close()
        self.record("working", 100.0)
        writer_store = LifecycleEvidenceStore(self.path)
        reader = self.store._connect()

        class ProviderCursor:
            def __init__(self, cursor):
                self._cursor = cursor

            def fetchall(self):
                rows = self._cursor.fetchall()
                writer_store.record(
                    agent_id="codex",
                    identity=self_identity,
                    session_id="session-1",
                    state="ended",
                    observed_at=200.0,
                    hook_event="Stop",
                )
                return rows

        class InterleavingConnection:
            def execute(self, statement, parameters=()):
                cursor = reader.execute(statement, parameters)
                if "FROM provider_evidence" in statement:
                    return ProviderCursor(cursor)
                return cursor

            def close(self):
                reader.close()

        self_identity = self.identity
        with mock.patch.object(
            self.store,
            "_connect",
            return_value=InterleavingConnection(),
        ):
            replay = self.replay()

        self.assertEqual(replay[0].sessions[0].state, "working")

    def test_concurrent_first_writers_initialize_schema_once(self):
        concurrent_path = os.path.join(self.tmp.name, "concurrent.sqlite3")
        start = threading.Barrier(8)
        errors = []

        def write(index):
            try:
                start.wait()
                LifecycleEvidenceStore(concurrent_path).record(
                    agent_id="codex",
                    identity=self.identity,
                    session_id=f"session-{index}",
                    state="working",
                    observed_at=float(index),
                    order_token=index,
                    hook_event="UserPromptSubmit",
                    complete=False,
                )
            except (OSError, sqlite3.Error) as error:
                errors.append(error)

        threads = [threading.Thread(target=write, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
