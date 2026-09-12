import json
import os
import tempfile
import time
import unittest
from unittest import mock

import codelight
from codelight_core import hook_commands
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.state import CodelightState


class LifecycleSnapshotRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = LifecycleEvidenceStore(
            os.path.join(self.tmp.name, "evidence.sqlite3")
        )
        self.identity = ProcessIdentity(
            pid=100,
            ppid=1,
            started_at="Sun Aug 30 04:01:53 2026",
            executable="/opt/homebrew/bin/opencode",
            command="/opt/homebrew/bin/opencode",
        )

    @mock.patch("codelight_core.hook_io.send_json", return_value=True)
    def test_snapshot_hook_persists_and_sends_one_complete_snapshot(self, send_json):
        input_text = json.dumps({
            "hook_event_name": "session.status.snapshot",
            "cwd": "/workspace",
            "complete": True,
            "sessions": [
                {"session_id": "busy", "state": "working"},
                {"session_id": "done", "state": "idle"},
            ],
        })
        with (
            mock.patch.object(codelight, "_lifecycle_evidence_store", self.store),
            mock.patch.object(
                codelight,
                "_hook_process_identity",
                return_value=self.identity,
            ),
        ):
            codelight.run_snapshot_hook("opencode", input_text=input_text)

        replay = self.store.replay({"opencode": frozenset({self.identity})})[0]
        self.assertTrue(replay.complete)
        self.assertEqual(
            tuple((session.session_id, session.state) for session in replay.sessions),
            (("busy", "working"), ("done", "idle")),
        )
        payload = send_json.call_args.args[1]
        self.assertEqual(payload["agent_id"], "opencode")
        self.assertEqual(len(payload["lifecycle_snapshot"]["sessions"]), 2)

    @mock.patch("codelight_core.hook_commands.hook_io.send_json", return_value=True)
    def test_partial_event_is_persisted_and_forwarded_as_incomplete(self, send_json):
        hook_commands.run_status_hook(
            "idle",
            agent_id="opencode",
            socket_path=os.path.join(self.tmp.name, "codelight.sock"),
            monitor_state_dir=os.path.join(self.tmp.name, "monitor"),
            normalize_agent_id=lambda value: value,
            input_text=json.dumps({
                "session_id": "done",
                "hook_event_name": "session.status",
                "provider_evidence_complete": False,
            }),
            evidence_store=self.store,
            process_identity=lambda _agent_id: self.identity,
        )

        replay = self.store.replay({"opencode": frozenset({self.identity})})[0]
        self.assertFalse(replay.complete)
        self.assertFalse(send_json.call_args.args[1]["provider_evidence_complete"])

    @mock.patch("codelight_core.hook_commands.hook_io.send_json", return_value=True)
    def test_status_without_process_identity_taints_older_evidence(self, _send_json):
        self.store.record_snapshot(
            agent_id="opencode",
            identity=self.identity,
            sessions=(),
            complete=True,
            observed_at=100.0,
        )

        hook_commands.run_status_hook(
            "working",
            agent_id="opencode",
            socket_path=os.path.join(self.tmp.name, "codelight.sock"),
            monitor_state_dir=os.path.join(self.tmp.name, "monitor"),
            normalize_agent_id=lambda value: value,
            input_text=json.dumps({"session_id": "busy"}),
            evidence_store=self.store,
            process_identity=lambda _agent_id: None,
        )

        replay = self.store.replay({"opencode": frozenset({self.identity})})
        self.assertFalse(replay[0].complete)
        self.assertEqual(replay[0].sessions, ())

    @mock.patch("codelight_core.hook_io.send_json", return_value=True)
    def test_snapshot_without_process_identity_taints_older_evidence(self, _send_json):
        self.store.record_snapshot(
            agent_id="opencode",
            identity=self.identity,
            sessions=(),
            complete=True,
            observed_at=100.0,
        )

        with (
            mock.patch.object(codelight, "_lifecycle_evidence_store", self.store),
            mock.patch.object(codelight, "_hook_process_identity", return_value=None),
        ):
            codelight.run_snapshot_hook(
                "opencode",
                input_text=json.dumps({"complete": True, "sessions": []}),
            )

        replay = self.store.replay({"opencode": frozenset({self.identity})})
        self.assertFalse(replay[0].complete)
        self.assertEqual(replay[0].sessions, ())

    def test_socket_handler_applies_complete_snapshot_atomically(self):
        state = CodelightState(
            default_agent_id="opencode",
            agent_registry={"opencode": {"display": "OpenCode"}},
            idle_window=600,
            idle_window_waiting=30,
            agent_process_states=lambda agent_ids: {
                agent_id: True for agent_id in agent_ids
            },
        )
        state.set_enabled_agents({"opencode"})
        with (
            mock.patch.object(codelight, "_state", state),
            mock.patch.object(codelight, "_push_locked"),
        ):
            codelight._handle_socket_message(None, {
                "boot_id": self.store.boot_id,
                "agent_id": "opencode",
                "observed_at": time.time(),
                "lifecycle_snapshot": {
                    "complete": True,
                    "sessions": [
                        {"session_id": "busy", "state": "working"},
                        {"session_id": "done", "state": "idle"},
                    ],
                },
            })

        self.assertEqual(state.power_authority_snapshot()["state"], "active")

    def test_foreign_epoch_snapshot_cannot_override_current_idle(self):
        state = CodelightState(
            default_agent_id="opencode",
            agent_registry={"opencode": {"display": "OpenCode"}},
            idle_window=600, idle_window_waiting=30,
            agent_process_states=lambda agents: {agent: True for agent in agents},
        )
        state.set_enabled_agents({"opencode"})
        state.update_provider_snapshot((), agent_id="opencode", complete=True, observed_at=time.time())
        with mock.patch.object(codelight, "_state", state):
            codelight._handle_socket_message(None, {
                "boot_id": "previous-boot", "agent_id": "opencode",
                "order_token": 1601000000000000,
                "lifecycle_snapshot": {"complete": True, "sessions": [{"session_id": "old", "state": "working"}]},
            })
        self.assertEqual(state.power_authority_snapshot()["state"], "idle")

    def test_malformed_socket_snapshot_invalidates_prior_idle_authority(self):
        state = CodelightState(
            default_agent_id="opencode",
            agent_registry={"opencode": {"display": "OpenCode"}},
            idle_window=600,
            idle_window_waiting=30,
            agent_process_states=lambda agent_ids: {
                agent_id: True for agent_id in agent_ids
            },
        )
        state.set_enabled_agents({"opencode"})
        state.update_provider_snapshot(
            (),
            agent_id="opencode",
            complete=True,
            observed_at=time.time(),
        )
        self.assertEqual(state.power_authority_snapshot()["state"], "idle")

        with (
            mock.patch.object(codelight, "_state", state),
            mock.patch.object(codelight, "_push_locked"),
        ):
            codelight._handle_socket_message(None, {
                "boot_id": self.store.boot_id,
                "agent_id": "opencode",
                "observed_at": time.time() + 1.0,
                "lifecycle_snapshot": "malformed",
            })

        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_object_session_id_makes_snapshot_incomplete(self):
        snapshot = codelight.lifecycle_snapshot.parse_provider_snapshot(
            {
                "complete": True,
                "sessions": [{"session_id": {"nested": "id"}, "state": "working"}],
            },
            "opencode",
        )

        self.assertFalse(snapshot.complete)
        self.assertEqual(snapshot.sessions, ())


if __name__ == "__main__":
    unittest.main()
