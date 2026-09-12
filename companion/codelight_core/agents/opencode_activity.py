"""Read-only execution projection for native OpenCode question waits.

QuestionTool awaits Question.ask's Deferred. Its running tool part survives
daemon restarts; terminal tool state resumes execution. No transcript text or
question/answer payload is selected. A DB read never creates provider authority:
only an already observed working/waiting session can be narrowed to idle.
"""
from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal, assert_never

from codelight_core.power_authority import AuthoritySession, SessionState

NativeState = Literal["question", "working", "idle", "unknown"]


@dataclass(frozen=True, slots=True)
class NativeSession:
    parent: str | None
    compacting: bool


def _native_state(db: sqlite3.Connection, sid: str) -> NativeState:
    row: tuple[str, str, int | None, str | None] | None = db.execute("""
        SELECT id, json_extract(data, '$.role'),
               json_extract(data, '$.time.completed'), json_extract(data, '$.finish')
        FROM message WHERE session_id=? ORDER BY time_created DESC, id DESC LIMIT 1
    """, (sid,)).fetchone()
    if row is None:
        return "unknown"
    message_id, role, completed, finish = row
    if role == "user":
        return "working"
    if role != "assistant":
        return "unknown"
    if completed is not None:
        return "idle" if completed > 0 and finish == "stop" else "unknown"
    tools: list[tuple[str, str]] = db.execute("""
        SELECT json_extract(data, '$.tool'), json_extract(data, '$.state.status')
        FROM part WHERE message_id=? AND json_extract(data, '$.type')='tool'
    """, (message_id,)).fetchall()
    question = False
    for name, status in tools:
        if status not in ("pending", "running", "completed", "error"):
            return "unknown"
        if status in ("pending", "running"):
            if name != "question" or status != "running":
                return "working"
            question = True
    return "question" if question else "working"


class OpenCodeActivity:
    def __init__(self, db_path: str) -> None:
        self._uri: str = Path(db_path).absolute().as_uri() + "?mode=ro"

    def resolve(self, sessions: tuple[AuthoritySession, ...]) -> tuple[AuthoritySession, ...]:
        candidates = tuple(s for s in sessions if s.agent_id == "opencode"
                           and s.state in ("working", "waiting"))
        if not candidates:
            return sessions
        try:
            with closing(sqlite3.connect(self._uri, uri=True, timeout=0.2)) as db:
                _ = db.execute("BEGIN")
                return self._resolve(db, sessions)
        except (sqlite3.Error, ValueError, TypeError):
            # An unreadable lifecycle source cannot weaken an active claim.
            return sessions

    def _resolve(self, db: sqlite3.Connection,
                 sessions: tuple[AuthoritySession, ...]) -> tuple[AuthoritySession, ...]:
        nodes: dict[str, NativeSession] = {}
        children: dict[str, list[str]] = {}
        rows: list[tuple[str, str | None, int | None]] = db.execute(
                "SELECT id, parent_id, time_compacting FROM session").fetchall()
        for sid, parent, compacting in rows:
            if not isinstance(sid, str) or not sid or (parent is not None and
                    (not isinstance(parent, str) or not parent)):
                return sessions
            nodes[sid] = NativeSession(parent, compacting is not None)
            if parent is not None:
                children.setdefault(parent, []).append(sid)
        observed: dict[str, list[SessionState]] = {}
        for session in sessions:
            if session.agent_id == "opencode":
                observed.setdefault(session.session_id, []).append(session.state)
        native: dict[str, NativeState] = {}

        def state(sid: str) -> NativeState:
            if sid not in native:
                native[sid] = _native_state(db, sid)
            return native[sid]

        def descendants(root: str) -> SessionState:
            visited = {root}
            pending = list(children.get(root, ()))
            active = False
            unknown = False
            while pending:
                sid = pending.pop()
                if sid in visited:
                    return "unknown"
                visited.add(sid)
                pending.extend(children.get(sid, ()))
                node = nodes[sid]
                raw = observed.get(sid, ())
                if "unknown" in raw:
                    unknown = True
                current = state(sid)
                if node.compacting:
                    active = True
                match current:
                    case "working":
                        active = True
                    case "unknown":
                        unknown = True
                    case "idle":
                        active |= any(s in ("working", "waiting") for s in raw)
                    case "question":
                        pass
                    case unreachable:
                        assert_never(unreachable)
            return "working" if active else "unknown" if unknown else "idle"

        result: list[AuthoritySession] = []
        for session in sessions:
            if session.agent_id != "opencode" or session.state not in ("working", "waiting"):
                result.append(session)
                continue
            node = nodes.get(session.session_id)
            if node is None or node.compacting:
                result.append(session)
                continue
            current = state(session.session_id)
            match current:
                case "question":
                    effective = descendants(session.session_id)
                    if node.parent is not None and node.parent not in nodes:
                        effective = "unknown"
                    result.append(replace(session, state=effective))
                case "working":
                    result.append(replace(session, state="working"))
                case "idle" | "unknown":
                    result.append(session)
                case unreachable:
                    assert_never(unreachable)
        return tuple(result)
