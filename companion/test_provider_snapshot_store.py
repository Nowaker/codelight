import os
import tempfile
import unittest

from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.power_authority import AuthoritySession


class ProviderSnapshotStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = LifecycleEvidenceStore(
            os.path.join(self.tmp.name, "evidence.sqlite3")
        )
        self.identity = ProcessIdentity(
            pid=100,
            ppid=1,
            started_at="darwin:1788076913:123456",
            executable="/opt/homebrew/bin/opencode",
            command="/opt/homebrew/bin/opencode",
        )

    def sessions(self, *states):
        return tuple(
            AuthoritySession(session_id, "opencode", state)
            for session_id, state in states
        )

    def replay(self):
        return self.store.replay({"opencode": frozenset({self.identity})})[0]

    def test_complete_snapshot_replaces_the_provider_session_set(self):
        self.store.record_snapshot(
            agent_id="opencode",
            identity=self.identity,
            sessions=self.sessions(("busy", "working"), ("done", "idle")),
            complete=True,
            observed_at=100.0,
        )

        first = self.replay()
        self.assertTrue(first.complete)
        self.assertEqual(
            tuple((session.session_id, session.state) for session in first.sessions),
            (("busy", "working"), ("done", "idle")),
        )

        self.store.record_snapshot(
            agent_id="opencode",
            identity=self.identity,
            sessions=(),
            complete=True,
            observed_at=200.0,
        )

        second = self.replay()
        self.assertTrue(second.complete)
        self.assertEqual(second.sessions, ())

    def test_failed_snapshot_preserves_activity_but_marks_it_incomplete(self):
        self.store.record_snapshot(
            agent_id="opencode",
            identity=self.identity,
            sessions=self.sessions(("busy", "working")),
            complete=True,
            observed_at=100.0,
        )
        self.store.record_snapshot(
            agent_id="opencode",
            identity=self.identity,
            sessions=(),
            complete=False,
            observed_at=200.0,
        )

        replay = self.replay()
        self.assertFalse(replay.complete)
        self.assertEqual(replay.sessions[0].state, "working")

    def test_older_event_does_not_repopulate_newer_complete_snapshot(self):
        self.store.record_snapshot(
            agent_id="opencode",
            identity=self.identity,
            sessions=(),
            complete=True,
            observed_at=200.0,
        )
        self.store.record(
            agent_id="opencode",
            identity=self.identity,
            session_id="session-stale",
            state="working",
            observed_at=100.0,
            hook_event="UserPromptSubmit",
            complete=False,
        )

        replayed = self.replay()
        self.assertTrue(replayed.complete)
        self.assertEqual(replayed.sessions, ())

    def test_directory_snapshots_are_persisted_as_independent_scopes(self):
        self.store.record_snapshot(
            agent_id="opencode",
            identity=self.identity,
            scope_id="/repo-a",
            sessions=self.sessions(("busy", "working")),
            complete=True,
            observed_at=100.0,
            order_token=100,
            lease_deadline_ns=1_000_000,
        )
        self.store.record_snapshot(
            agent_id="opencode",
            identity=self.identity,
            scope_id="/repo-b",
            sessions=(),
            complete=True,
            observed_at=200.0,
            order_token=200,
            lease_deadline_ns=1_000_000,
        )

        replayed = self.store.replay(
            {"opencode": frozenset({self.identity})},
            now_order_token=500,
        )
        self.assertEqual(len(replayed), 2)
        by_scope = {provider.scope_id: provider for provider in replayed}
        self.assertEqual(by_scope["/repo-a"].sessions[0].state, "working")
        self.assertEqual(by_scope["/repo-b"].sessions, ())

    def test_expired_snapshot_lease_replays_as_unknown(self):
        self.store.record_snapshot(
            agent_id="opencode",
            identity=self.identity,
            sessions=(),
            complete=True,
            observed_at=100.0,
            order_token=100,
            lease_deadline_ns=150,
        )

        replayed = self.store.replay(
            {"opencode": frozenset({self.identity})},
            now_order_token=200,
        )[0]
        self.assertFalse(replayed.complete)
        self.assertEqual(replayed.sessions, ())

    def test_clock_rollback_does_not_reject_newer_event_order(self):
        self.store.record(
            agent_id="opencode",
            identity=self.identity,
            session_id="session-1",
            state="ended",
            observed_at=200.0,
            order_token=100,
            hook_event="Stop",
        )
        self.store.record(
            agent_id="opencode",
            identity=self.identity,
            session_id="session-1",
            state="working",
            observed_at=100.0,
            order_token=200,
            hook_event="UserPromptSubmit",
        )

        self.assertEqual(self.replay().sessions[0].state, "working")

    def test_newer_provider_event_does_not_suppress_another_session(self):
        self.store.record(
            agent_id="opencode",
            identity=self.identity,
            session_id="session-newer",
            state="working",
            observed_at=200.0,
            order_token=200,
            hook_event="UserPromptSubmit",
            complete=False,
        )
        self.store.record(
            agent_id="opencode",
            identity=self.identity,
            session_id="session-older",
            state="working",
            observed_at=100.0,
            order_token=100,
            hook_event="UserPromptSubmit",
            complete=False,
        )

        sessions = {session.session_id for session in self.replay().sessions}
        self.assertEqual(sessions, {"session-newer", "session-older"})

    def test_equal_tick_working_outranks_completion(self):
        self.store.record(
            agent_id="opencode",
            identity=self.identity,
            session_id="session-1",
            state="working",
            observed_at=100.0,
            order_token=100,
            hook_event="UserPromptSubmit",
        )
        self.store.record(
            agent_id="opencode",
            identity=self.identity,
            session_id="session-1",
            state="ended",
            observed_at=100.0,
            order_token=100,
            hook_event="Stop",
        )

        self.assertEqual(self.replay().sessions[0].state, "working")


if __name__ == "__main__":
    unittest.main()
