from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from codelight_core.agents.registry import AgentRegistry
from codelight_core.agents.typescript_adapter import TypeScriptAdapter
from codelight_core import hooks as hooks_core
from codelight_core import process_generation
from codelight_core import service as service_core
from codelight_core import vscode as vscode_core


def _process_command_lines() -> tuple[str, ...] | None:
    try:
        result = subprocess.run(
            ["ps", "-axo", "command="],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return tuple(line for line in result.stdout.splitlines() if line.strip())


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    ppid: int
    started_at: str
    executable: str
    command: str


@dataclass(frozen=True, slots=True)
class ProcessInventory:
    identities: tuple[ProcessIdentity, ...]
    unresolved: frozenset[tuple[str, str]]


def process_generation_key(agent_id: str, identity: ProcessIdentity) -> str:
    value = "\0".join((
        agent_id,
        str(identity.pid),
        identity.started_at,
        identity.executable,
    ))
    return hashlib.sha256(value.encode()).hexdigest()


def authority_scope_key(
    agent_id: str,
    identity: ProcessIdentity,
    scope_id: str,
) -> str:
    generation = process_generation_key(agent_id, identity)
    return hashlib.sha256(f"{generation}\0{scope_id}".encode()).hexdigest()


def _process_rows() -> ProcessInventory | None:
    process_environment = os.environ.copy()
    process_environment["LC_ALL"] = "C"
    try:
        result = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,command="],
            capture_output=True,
            text=True,
            check=True,
            env=process_environment,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    rows = []
    unresolved = set()
    for line in result.stdout.splitlines():
        fields = line.split(None, 2)
        if len(fields) != 3:
            continue
        try:
            pid = int(fields[0])
            ppid = int(fields[1])
        except ValueError:
            continue
        command = fields[2]
        executable = command.split(maxsplit=1)[0].strip("'\"")
        generation = process_generation.process_generation(pid)
        if generation is None:
            unresolved.add((executable, command))
            continue
        rows.append(ProcessIdentity(
            pid=pid,
            ppid=ppid,
            started_at=generation,
            executable=executable,
            command=command,
        ))
    return ProcessInventory(tuple(rows), frozenset(unresolved))


class AgentProcessProbe:
    def __init__(
        self,
        executables_by_agent: dict[str, tuple[str, ...]],
        *,
        process_matchers: dict[str, Callable[[str], bool]] | None = None,
        command_lines: Callable[[], tuple[str, ...] | None] = _process_command_lines,
        process_rows: Callable[[], ProcessInventory | None] = _process_rows,
    ) -> None:
        self._executables_by_agent = executables_by_agent
        self._process_matchers = process_matchers or {}
        self._command_lines = command_lines
        self._process_rows = process_rows

    def _accepts(self, agent_id: str, command: str) -> bool:
        matcher = self._process_matchers.get(agent_id)
        return matcher is None or matcher(command)

    def _matches(self, agent_id: str, command_lines: tuple[str, ...]) -> bool:
        expected = set(self._executables_by_agent.get(agent_id, ()))
        for command_line in command_lines:
            if not self._accepts(agent_id, command_line):
                continue
            executable_tokens = (
                os.path.basename(token.strip("'\""))
                for token in command_line.split()
            )
            if any(token in expected for token in executable_tokens):
                return True
        return False

    def snapshot(self, agent_ids: set[str]) -> dict[str, bool | None]:
        command_lines = self._command_lines()
        if command_lines is None:
            return {agent_id: None for agent_id in agent_ids}
        states: dict[str, bool | None] = {}
        for agent_id in agent_ids:
            states[agent_id] = (
                self._matches(agent_id, command_lines)
                if self._executables_by_agent.get(agent_id)
                else None
            )
        return states

    def __call__(self, agent_id: str) -> bool | None:
        return self.snapshot({agent_id})[agent_id]

    def identities(
        self,
        agent_ids: set[str],
    ) -> dict[str, frozenset[ProcessIdentity]] | None:
        inventory = self._process_rows()
        if inventory is None:
            return None
        expected_by_agent = {
            agent_id: set(self._executables_by_agent.get(agent_id, ()))
            for agent_id in agent_ids
        }
        if any(
            os.path.basename(executable) in expected_by_agent[agent_id]
            and self._accepts(agent_id, command)
            for executable, command in inventory.unresolved
            for agent_id in agent_ids
        ):
            return None
        return {
            agent_id: frozenset(
                row for row in inventory.identities
                if os.path.basename(row.executable)
                in expected_by_agent[agent_id]
                and self._accepts(agent_id, row.command)
            )
            for agent_id in agent_ids
        }

    def nearest_ancestor(
        self,
        agent_id: str,
        start_pid: int,
    ) -> ProcessIdentity | None:
        inventory = self._process_rows()
        if inventory is None:
            return None
        expected = set(self._executables_by_agent.get(agent_id, ()))
        by_pid = {row.pid: row for row in inventory.identities}
        seen = set()
        current = by_pid.get(start_pid)
        while current is not None and current.pid not in seen:
            seen.add(current.pid)
            if (
                os.path.basename(current.executable) in expected
                and self._accepts(agent_id, current.command)
            ):
                return current
            current = by_pid.get(current.ppid)
        return None


def detect_installed_agents(agent_registry: AgentRegistry) -> set[str]:
    return vscode_core.detect_installed_agents(
        agent_executables=agent_registry.executables_by_agent(),
        agent_vscode_extensions=agent_registry.vscode_extensions_by_agent(),
        which=shutil.which, run=subprocess.run)


def parse_agent_set(value: str | None, supported_agents: set[str]) -> set[str]:
    return vscode_core.parse_agent_set(value, supported_agents)


def install_vscode_extension(script_path: str, secret: str = "",
                             ws_port: int = 8765) -> None:
    vscode_core.install_vscode_extension(
        script_path, secret, ws_port, which=shutil.which, run=subprocess.run)


def uninstall_vscode_extension() -> None:
    vscode_core.uninstall_vscode_extension(
        which=shutil.which, run=subprocess.run)


def install_service(
    *,
    script_path: str,
    name: str,
    secret: str,
    ws_port: int,
    listen_host: str = "127.0.0.1",
    verbose: bool,
    remote_control: bool = False,
    permission_timeout: int = 60,
    agents: set[str] | None = None,
) -> None:
    service_core.install_service(
        name=name,
        secret=secret,
        ws_port=ws_port,
        listen_host=listen_host,
        verbose=verbose,
        script_path=script_path,
        remote_control=remote_control,
        permission_timeout=permission_timeout,
        agents=agents,
        run=subprocess.run,
    )


def install_agent_hooks(
    *,
    agent_registry: AgentRegistry,
    enabled_agents: set[str],
    script_path: str,
    hook_wait_ceiling: int,
    remote_permissions: bool = False,
    remote_questions: bool = False,
    permission_timeout: int = 60,
    log=None,
) -> None:
    agent_registry.install_hooks(
        enabled_agents=enabled_agents,
        script_path=script_path,
        hook_wait_ceiling=hook_wait_ceiling,
        remote_permissions=remote_permissions,
        remote_questions=remote_questions,
        permission_timeout=permission_timeout,
        log=log,
    )


def uninstall(
    *,
    agent_registry: AgentRegistry,
    policy_path: str,
    config_home: str,
    socket_path: str,
    monitor_state_dir: str,
) -> None:
    """Remove codelight hooks, local state, service, and optional clients."""
    for path in agent_registry.removable_hook_paths():
        hooks_core.remove_matcher_group_hooks(path)

    for path in agent_registry.removable_files():
        service_core.remove_file(path)
    for path in agent_registry.removable_adapter_files():
        if TypeScriptAdapter.remove_if_owned(path):
            print(f"[uninstall] removed {path}")
        elif os.path.lexists(path):
            print(f"[uninstall] preserved unowned file: {path}")
    for path in agent_registry.removable_empty_dirs():
        service_core.remove_empty_dir(path)

    service_core.remove_file(policy_path)
    service_core.remove_empty_dir(config_home)

    for path in [socket_path, monitor_state_dir]:
        service_core.remove_path(path)

    service_core.uninstall_service(run=subprocess.run)
    uninstall_vscode_extension()

    print("[uninstall] done")
