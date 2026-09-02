from __future__ import annotations

import json
import math
import os
import sys
import time
from dataclasses import dataclass
from typing import Callable

from codelight_core.agents import base, claude


ACTIVE_WINDOW_MS = 100_000
WAITING_WINDOW_MS = 900_000
POLL_INTERVAL = 5.0


SPEC = base.AgentSpec(
    agent_id="claude-desktop",
    display="Claude Desktop",
    color=claude.SPEC.color,
    logo_svg=claude.SPEC.logo_svg,
    logo_bitmap=claude.SPEC.logo_bitmap,
)


@dataclass(frozen=True, slots=True)
class DesktopSession:
    session_id: str
    cwd: str
    last_activity_ms: int
    archived: bool


def status_for_metadata(
    *,
    now_ms: int,
    last_activity_ms: int,
    archived: bool,
) -> str:
    if archived:
        return "ended"
    if last_activity_ms > now_ms:
        return "unknown"
    age_ms = now_ms - last_activity_ms
    if age_ms < ACTIVE_WINDOW_MS:
        return "working"
    if age_ms < WAITING_WINDOW_MS:
        return "waiting"
    return "idle"


def default_sessions_root() -> str:
    if sys.platform == "darwin":
        return os.path.expanduser(
            "~/Library/Application Support/Claude/claude-code-sessions"
        )
    return os.path.expanduser("~/.config/Claude/claude-code-sessions")


def _read_session(path: str) -> DesktopSession | None:
    try:
        with open(path, encoding="utf-8") as stream:
            data = json.load(stream)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    session_id = str(data.get("cliSessionId") or data.get("sessionId") or "")
    activity_value = data.get("lastActivityAt")
    archived_value = data.get("isArchived", False)
    if (
        not session_id
        or isinstance(activity_value, bool)
        or not isinstance(activity_value, (int, float))
        or not math.isfinite(activity_value)
        or activity_value < 0
        or not isinstance(archived_value, bool)
    ):
        return None
    return DesktopSession(
        session_id=session_id,
        cwd=str(data.get("cwd") or data.get("originCwd") or ""),
        last_activity_ms=int(activity_value),
        archived=archived_value,
    )


def scan_sessions(root: str) -> tuple[DesktopSession, ...]:
    if not os.path.isdir(root):
        return ()
    latest: dict[str, DesktopSession] = {}
    for directory, _, filenames in os.walk(root):
        for filename in filenames:
            if not filename.startswith("local_") or not filename.endswith(".json"):
                continue
            session = _read_session(os.path.join(directory, filename))
            if session is None:
                continue
            previous = latest.get(session.session_id)
            if previous is None or session.last_activity_ms > previous.last_activity_ms:
                latest[session.session_id] = session
    return tuple(latest.values())


class ClaudeDesktopAgent:
    def __init__(self, sessions_root: str) -> None:
        self._sessions_root = sessions_root

    def run_listener(self, ctx: base.ListenerContext) -> None:
        tracked: set[str] = set()
        while not ctx.shutdown.is_set():
            sessions = scan_sessions(self._sessions_root)
            current = {session.session_id for session in sessions}
            now_ms = int(time.time() * 1000)
            for session in sessions:
                status = status_for_metadata(
                    now_ms=now_ms,
                    last_activity_ms=session.last_activity_ms,
                    archived=session.archived,
                )
                ctx.report_status(
                    session.session_id,
                    status,
                    "claude-desktop",
                    cwd=session.cwd,
                )
            for session_id in tracked - current:
                ctx.report_status(session_id, "idle", "claude-desktop")
            tracked = current
            ctx.shutdown.wait(POLL_INTERVAL)


def build_integration(
    config: dict,
    *,
    log: Callable[[str], None] | None = None,
) -> base.AgentIntegration:
    del log
    sessions_root = os.path.expanduser(
        str(config.get("sessions_root") or default_sessions_root())
    )
    agent = ClaudeDesktopAgent(sessions_root)
    return base.AgentIntegration(
        spec=SPEC,
        agent=agent,
        background_listener=agent.run_listener,
    )
