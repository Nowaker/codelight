import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from codelight_core import hook_commands
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore


STARTED_AT = "Sun Aug 30 04:01:53 2026"


def process(
    pid: int,
    ppid: int,
    executable: str,
    *,
    started_at: str = STARTED_AT,
) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        ppid=ppid,
        started_at=started_at,
        executable=executable,
        command=executable,
    )


class LifecycleEvidenceStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "evidence.sqlite3")
        self.store = LifecycleEvidenceStore(self.path)
        self.codex = process(100, 1, "/opt/homebrew/bin/codex")

    def live(self, identity=None):
        return {"codex": frozenset({identity or self.codex})}

    def test_replays_active_only_for_the_same_process_generation(self):
        self.store.record(
            agent_id="codex",
            identity=self.codex,
            session_id="session-1",
            state="working",
            observed_at=100.0,
            hook_event="UserPromptSubmit",
        )

        replay = self.store.replay(self.live())
        self.assertEqual(replay[0].agent_id, "codex")
        self.assertEqual(replay[0].identity, self.codex)
        self.assertEqual(replay[0].sessions[0].state, "working")
        self.assertEqual(replay[0].sessions[0].observed_at, 100.0)

        reused_pid = process(
            100,
            1,
            "/opt/homebrew/bin/codex",
            started_at="Sun Aug 30 05:01:53 2026",
        )
        replay = self.store.replay(self.live(reused_pid))
        self.assertEqual(replay[0].identity, reused_pid)
        self.assertFalse(replay[0].complete)
        self.assertEqual(replay[0].sessions, ())

    def test_completion_retains_provider_idle_evidence(self):
        self.store.record(
            agent_id="codex",
            identity=self.codex,
            session_id="session-1",
            state="working",
            observed_at=100.0,
            hook_event="UserPromptSubmit",
        )
        self.store.record(
            agent_id="codex",
            identity=self.codex,
            session_id="session-1",
            state="ended",
            observed_at=110.0,
            hook_event="Stop",
        )

        replay = self.store.replay(self.live())
        self.assertEqual(len(replay), 1)
        self.assertEqual(replay[0].sessions[0].state, "ended")
        self.assertEqual(replay[0].observed_at, 110.0)

    def test_does_not_persist_process_command_arguments(self):
        identity = ProcessIdentity(
            pid=self.codex.pid,
            ppid=self.codex.ppid,
            started_at=self.codex.started_at,
            executable=self.codex.executable,
            command="codex --runtime-argument private-value",
        )
        self.store.record(
            agent_id="codex",
            identity=identity,
            session_id="session-1",
            state="working",
            observed_at=100.0,
            hook_event="UserPromptSubmit",
        )

        with open(self.store._path, "rb") as evidence_file:
            contents = evidence_file.read()
        self.assertNotIn(b"private-value", contents)

    def test_malformed_store_replays_no_evidence(self):
        with open(self.store._boot.verified_path(), "wb") as evidence_file:
            evidence_file.write(b"not sqlite")

        replay = self.store.replay(self.live())
        self.assertFalse(replay[0].complete)
        self.assertEqual(replay[0].sessions, ())

    def test_malformed_session_row_makes_provider_incomplete(self):
        self.store.record(
            agent_id="codex",
            identity=self.codex,
            session_id="session-1",
            state="ended",
            observed_at=100.0,
            hook_event="Stop",
        )
        connection = sqlite3.connect(self.store._path)
        try:
            with connection:
                connection.execute(
                    "UPDATE session_evidence SET state = 'malformed'"
                )
        finally:
            connection.close()

        replay = self.store.replay(self.live())[0]
        self.assertFalse(replay.complete)
        self.assertEqual(replay.sessions, ())

    def test_older_event_cannot_replace_newer_completion(self):
        for state, observed_at in (("ended", 200.0), ("working", 100.0)):
            self.store.record(
                agent_id="codex",
                identity=self.codex,
                session_id="session-1",
                state=state,
                observed_at=observed_at,
                hook_event="Stop" if state == "ended" else "PreToolUse",
            )

        replay = self.store.replay(self.live())
        self.assertEqual(replay[0].sessions[0].state, "ended")

    def test_live_generation_without_evidence_replays_explicit_unknown(self):
        self.store.record(
            agent_id="codex",
            identity=self.codex,
            session_id="session-1",
            state="ended",
            observed_at=100.0,
            hook_event="Stop",
        )
        second = process(200, 1, "/opt/homebrew/bin/codex", started_at="gen-2")

        replay = self.store.replay({"codex": frozenset({self.codex, second})})
        by_identity = {provider.identity: provider for provider in replay}
        self.assertTrue(by_identity[self.codex].complete)
        self.assertFalse(by_identity[second].complete)


class DurableStatusHookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "evidence.sqlite3")
        self.store = LifecycleEvidenceStore(self.path)
        self.codex = process(100, 1, "/opt/homebrew/bin/codex")
        self.payload = json.dumps({
            "session_id": "session-1",
            "hook_event_name": "UserPromptSubmit",
            "cwd": "/workspace",
        })

    @mock.patch("codelight_core.hook_commands.hook_io.send_json", return_value=True)
    def test_successful_socket_delivery_also_persists_evidence(self, _send_json):
        hook_commands.run_status_hook(
            "working",
            agent_id="codex",
            socket_path=os.path.join(self.tmp.name, "codelight.sock"),
            monitor_state_dir=os.path.join(self.tmp.name, "monitor"),
            normalize_agent_id=lambda value: value,
            input_text=self.payload,
            evidence_store=self.store,
            process_identity=lambda _agent_id: self.codex,
        )

        replay = self.store.replay({"codex": frozenset({self.codex})})
        self.assertEqual(replay[0].sessions[0].state, "working")

    @mock.patch("codelight_core.hook_commands.hook_io.send_json", return_value=False)
    def test_daemon_down_working_then_ended_replays_idle(self, _send_json):
        common = {
            "agent_id": "codex",
            "socket_path": os.path.join(self.tmp.name, "codelight.sock"),
            "monitor_state_dir": os.path.join(self.tmp.name, "monitor"),
            "normalize_agent_id": lambda value: value,
            "evidence_store": self.store,
            "process_identity": lambda _agent_id: self.codex,
        }
        hook_commands.run_status_hook(
            "working", input_text=self.payload, **common)
        hook_commands.run_status_hook(
            "ended",
            input_text=json.dumps({
                "session_id": "session-1",
                "hook_event_name": "Stop",
            }),
            **common,
        )

        replay = self.store.replay({"codex": frozenset({self.codex})})
        self.assertEqual(len(replay), 1)
        self.assertEqual(replay[0].sessions[0].state, "ended")


if __name__ == "__main__":
    unittest.main()
