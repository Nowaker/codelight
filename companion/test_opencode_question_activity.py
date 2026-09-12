"""Native SQLite lifecycle fixtures, not mocked query responses."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from codelight_core.agents.opencode_activity import OpenCodeActivity
from codelight_core.power_authority import AuthoritySession, SessionState


class QuestionFixture(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "opencode.db"
        self.db = sqlite3.connect(self.path)
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE session (id TEXT PRIMARY KEY, parent_id TEXT, time_compacting INTEGER);
            CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, time_created INTEGER, data TEXT);
            CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT, data TEXT);
        """)
        self.resolver = OpenCodeActivity(str(self.path))
        self.claims: dict[str, SessionState] = {}

    def session(self, sid, parent=None, *, completed=False, question=False):
        self.claims[sid] = "idle" if completed else "working"
        self.db.execute("INSERT INTO session VALUES (?, ?, NULL)", (sid, parent))
        self.db.execute("INSERT INTO message VALUES (?, ?, 1, ?)", (
            sid + "msg", sid, json.dumps({"role": "assistant", "finish": "stop" if completed else None, "time": {
                "created": 1, **({"completed": 2} if completed else {})}})))
        if question:
            self.tool(sid, "question")
        self.db.commit()

    def tool(self, sid, name, status="running"):
        self.db.execute("INSERT INTO part VALUES (?, ?, ?, ?)", (
            sid + name, sid + "msg", sid,
            json.dumps({"type": "tool", "tool": name, "state": {"status": status}})))
        self.db.commit()

class QuestionActivityTests(QuestionFixture):
    def resolve(self, state: SessionState = "working") -> SessionState:
        claims = (AuthoritySession("parent", "opencode", state),) + tuple(
            AuthoritySession(sid, "opencode", value)
            for sid, value in self.claims.items() if sid != "parent"
        )
        return self.resolver.resolve(claims, frozenset({"opencode"}))[0].state

    def test_question_without_descendants_is_idle_on_first_read(self):
        self.session("parent", question=True)
        self.assertEqual(self.resolve(), "idle")

    def test_working_descendant_makes_effective_parent_working(self):
        self.session("parent", question=True)
        self.session("child", "parent")
        self.assertEqual(self.resolve(), "working")

    def test_completed_descendant_allows_parent_idle(self):
        self.session("parent", question=True)
        self.session("child", "parent", completed=True)
        self.assertEqual(self.resolve(), "idle")

    def test_nested_working_descendant_makes_parent_working(self):
        self.session("parent", question=True)
        self.session("child", "parent", completed=True)
        self.session("grandchild", "child")
        self.assertEqual(self.resolve(), "working")

    def test_nested_question_without_work_is_idle(self):
        self.session("parent", question=True)
        self.session("child", "parent", question=True)
        self.assertEqual(self.resolve(), "idle")

    def test_other_parallel_tool_keeps_question_parent_working(self):
        self.session("parent", question=True)
        self.tool("parent", "bash")
        self.assertEqual(self.resolve(), "working")

    def test_question_reply_restores_working_without_restarting_resolver(self):
        self.session("parent", question=True)
        self.assertEqual(self.resolve(), "idle")
        self.db.execute("UPDATE part SET data=json_set(data, '$.state.status', 'completed')")
        self.db.commit()
        self.assertEqual(self.resolve("waiting"), "working")

    def test_child_start_and_finish_are_visible_without_parent_event(self):
        self.session("parent", question=True)
        self.assertEqual(self.resolve(), "idle")
        self.session("child", "parent")
        self.assertEqual(self.resolve(), "working")
        self.db.execute("UPDATE message SET data=json_set(data, '$.time.completed', 2, '$.finish', 'stop') WHERE session_id='child'")
        self.db.commit()
        self.claims["child"] = "idle"
        self.assertEqual(self.resolve(), "idle")

    def test_missing_child_message_fails_closed(self):
        self.session("parent", question=True)
        self.db.execute("INSERT INTO session VALUES ('child', 'parent', NULL)")
        self.db.commit()
        self.claims["child"] = "unknown"
        self.assertEqual(self.resolve(), "unknown")

    def test_cycle_fails_closed(self):
        self.session("parent", "child", question=True)
        self.session("child", "parent", completed=True)
        self.assertEqual(self.resolve(), "unknown")

    def test_unknown_live_child_overrides_completed_database_message(self):
        self.session("parent", question=True)
        self.session("child", "parent", completed=True)
        result = self.resolver.resolve((AuthoritySession("parent", "opencode", "working"),
                                        AuthoritySession("child", "opencode", "unknown")), frozenset({"opencode"}))
        self.assertEqual(result[0].state, "unknown")

    def test_independent_work_and_other_provider_wait_are_preserved(self):
        self.session("parent", question=True)
        sessions = (AuthoritySession("parent", "opencode", "working"),
                    AuthoritySession("other", "opencode", "working"),
                    AuthoritySession("claude", "claude", "waiting"))
        self.assertEqual([s.state for s in self.resolver.resolve(sessions, frozenset({"opencode"}))],
                         ["idle", "working", "waiting"])

    def test_compaction_is_work_even_with_outstanding_question(self):
        self.session("parent", question=True)
        self.db.execute("UPDATE session SET time_compacting=3")
        self.db.commit()
        self.assertEqual(self.resolve(), "working")

    def test_question_rejection_restores_working(self):
        self.session("parent", question=True)
        self.db.execute("UPDATE part SET data=json_set(data, '$.state.status', 'error')")
        self.db.commit()
        self.assertEqual(self.resolve("waiting"), "working")

    def test_unreadable_database_preserves_existing_activity(self):
        self.session("parent", question=True)
        self.db.execute("DROP TABLE part")
        self.db.commit()
        self.assertEqual(self.resolve(), "working")

    def test_malformed_child_payload_cannot_prove_idle(self):
        self.session("parent", question=True)
        self.session("child", "parent")
        self.db.execute("UPDATE message SET data='broken' WHERE session_id='child'")
        self.db.commit()
        self.assertEqual(self.resolve(), "working")

    def test_malformed_parent_data_cannot_prove_idle(self):
        self.session("parent", question=True)
        self.db.execute("INSERT INTO session VALUES ('child', '', NULL)")
        self.db.commit()
        self.assertEqual(self.resolve(), "working")

    def test_newer_user_message_preserves_execution(self):
        self.session("parent", question=True)
        self.db.execute("INSERT INTO message VALUES ('new', 'parent', 3, ?)",
                        (json.dumps({"role": "user"}),))
        self.db.commit()
        self.assertEqual(self.resolve(), "working")

    def test_expired_unknown_claim_cannot_be_downgraded_from_database(self):
        self.session("parent", question=True)
        self.assertEqual(self.resolve("unknown"), "unknown")

    def test_tool_call_completion_is_not_terminal_child_execution(self):
        self.session("parent", question=True)
        self.session("child", "parent", completed=True)
        self.db.execute("UPDATE message SET data=json_set(data, '$.finish', 'tool-calls') WHERE session_id='child'")
        self.db.commit()
        self.assertEqual(self.resolve(), "unknown")

    def test_daemon_reconnect_reloads_outstanding_question(self):
        self.session("parent", question=True)
        self.resolver = OpenCodeActivity(str(self.path))
        self.assertEqual(self.resolve("waiting"), "idle")

    def test_registry_and_scoped_state_publish_parent_idle(self):
        from codelight_core.agents import opencode
        from codelight_core.agents.registry import AgentRegistry
        from codelight_core.state import CodelightState
        import time

        self.session("parent", question=True)
        registry = AgentRegistry(modules=[opencode],
                                 agents_config={"opencode": {"db_path": str(self.path)}})
        state = CodelightState(default_agent_id="opencode", agent_registry={},
                               idle_window=60, idle_window_waiting=60,
                               agent_process_alive=lambda _: True,
                               activity_resolver=registry.resolve_activity)
        state.set_enabled_agents({"opencode"})
        state.update_provider_snapshot((AuthoritySession("parent", "opencode", "working"),),
                                       agent_id="opencode", complete=True,
                                       observed_at=time.time(), authority_scope="pid:123:directory",
                                       authority_generation="generation",
                                       lease_deadline_ns=time.monotonic_ns() + 60_000_000_000)
        from codelight_core.evidence_order import evidence_order, UNKNOWN_RANK
        state.record_process_inventory("opencode", True)
        state.reconcile_replayed_authority("opencode", frozenset({"generation"}), frozenset(),
                                          evidence_order(time.monotonic_ns(), UNKNOWN_RANK))
        self.assertEqual(state.power_authority_snapshot()["providers"]["opencode"],
                         {"state": "idle", "activeSessions": 0})


if __name__ == "__main__":
    unittest.main()
