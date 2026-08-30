from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity


@dataclass(frozen=True, slots=True)
class TaintOperation:
    agent_id: str
    identity: ProcessIdentity | None
    scope_id: str | None
    order: EvidenceOrder
    path: str


class InvalidTaintMarkerError(ValueError):
    pass


class GenerationTaintStore:
    def __init__(self, directory: str) -> None:
        self._directory = directory

    @staticmethod
    def _prefix(agent_id: str, identity: ProcessIdentity, scope_id: str) -> str:
        value = "\0".join((
            "scope",
            agent_id,
            str(identity.pid),
            identity.started_at,
            identity.executable,
            scope_id,
        ))
        return hashlib.sha256(value.encode()).hexdigest()

    @staticmethod
    def _agent_prefix(agent_id: str) -> str:
        return hashlib.sha256(f"agent\0{agent_id}".encode()).hexdigest()

    @staticmethod
    def _same_identity(
        left: ProcessIdentity | None,
        right: ProcessIdentity | None,
    ) -> bool:
        if left is None or right is None:
            return left is right
        return (
            left.pid,
            left.started_at,
            left.executable,
        ) == (
            right.pid,
            right.started_at,
            right.executable,
        )

    def _ensure_directory(self) -> None:
        os.makedirs(self._directory, mode=0o700, exist_ok=True)
        os.chmod(self._directory, 0o700)

    @staticmethod
    def _unlink(path: str) -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            return

    def _write(
        self,
        prefix: str,
        payload: dict[str, str | int | None],
        order: EvidenceOrder,
    ) -> str:
        self._ensure_directory()
        marker_name = (
            f"{prefix}-{order.token:020d}-{order.authority_rank}-"
            f"{order.operation_id}.taint"
        )
        marker_path = os.path.join(self._directory, marker_name)
        descriptor = os.open(
            marker_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        try:
            written = 0
            while written < len(encoded):
                written += os.write(descriptor, encoded[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return marker_path

    def mark(
        self,
        agent_id: str,
        identity: ProcessIdentity,
        scope_id: str,
        order: EvidenceOrder,
    ) -> TaintOperation:
        path = self._write(
            self._prefix(agent_id, identity, scope_id),
            {
                "kind": "scope",
                "agent_id": agent_id,
                "pid": identity.pid,
                "ppid": identity.ppid,
                "generation": identity.started_at,
                "executable": identity.executable,
                "scope_id": scope_id,
                "order_token": order.token,
                "authority_rank": order.authority_rank,
                "operation_id": order.operation_id,
            },
            order,
        )
        return TaintOperation(agent_id, identity, scope_id, order, path)

    def mark_agent(self, agent_id: str, order: EvidenceOrder) -> TaintOperation:
        path = self._write(
            self._agent_prefix(agent_id),
            {
                "kind": "agent",
                "agent_id": agent_id,
                "pid": None,
                "ppid": None,
                "generation": None,
                "executable": None,
                "scope_id": None,
                "order_token": order.token,
                "authority_rank": order.authority_rank,
                "operation_id": order.operation_id,
            },
            order,
        )
        return TaintOperation(agent_id, None, None, order, path)

    @staticmethod
    def _parse(path: str) -> TaintOperation:
        with open(path, encoding="utf-8") as marker:
            payload = json.load(marker)
        if not isinstance(payload, dict):
            raise InvalidTaintMarkerError
        agent_id = payload.get("agent_id")
        operation_id = payload.get("operation_id")
        token = payload.get("order_token")
        rank = payload.get("authority_rank")
        if (
            not isinstance(agent_id, str)
            or not agent_id
            or not isinstance(operation_id, str)
            or not operation_id
            or not isinstance(token, int)
            or isinstance(token, bool)
            or not isinstance(rank, int)
            or isinstance(rank, bool)
            or rank not in (0, 1, 2)
        ):
            raise InvalidTaintMarkerError
        order = EvidenceOrder(token, rank, operation_id)
        if payload.get("kind") == "agent":
            return TaintOperation(agent_id, None, None, order, path)
        scope_id = payload.get("scope_id")
        pid = payload.get("pid")
        ppid = payload.get("ppid")
        generation = payload.get("generation")
        executable = payload.get("executable")
        if (
            payload.get("kind") != "scope"
            or not isinstance(scope_id, str)
            or not isinstance(pid, int)
            or isinstance(pid, bool)
            or not isinstance(ppid, int)
            or isinstance(ppid, bool)
            or not isinstance(generation, str)
            or not generation
            or not isinstance(executable, str)
            or not executable
        ):
            raise InvalidTaintMarkerError
        identity = ProcessIdentity(pid, ppid, generation, executable, executable)
        return TaintOperation(agent_id, identity, scope_id, order, path)

    def attempts(self) -> tuple[tuple[TaintOperation, ...], bool]:
        try:
            with os.scandir(self._directory) as entries:
                paths = tuple(
                    entry.path for entry in entries if entry.name.endswith(".taint")
                )
        except FileNotFoundError:
            return (), False
        operations = []
        malformed = False
        for path in paths:
            try:
                operations.append(self._parse(path))
            except FileNotFoundError:
                continue
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                malformed = True
        return tuple(operations), malformed

    def clear_success(self, operation: TaintOperation) -> None:
        self._unlink(operation.path)

    def clear_scope_through(self, operation: TaintOperation) -> None:
        attempts, _malformed = self.attempts()
        for candidate in attempts:
            if (
                candidate.agent_id == operation.agent_id
                and self._same_identity(candidate.identity, operation.identity)
                and candidate.scope_id == operation.scope_id
                and candidate.order <= operation.order
            ):
                self._unlink(candidate.path)

    def has_agent_taint(self, agent_id: str) -> bool:
        attempts, malformed = self.attempts()
        return malformed or any(
            operation.agent_id == agent_id and operation.identity is None
            for operation in attempts
        )

    def clear_agent_through(
        self,
        agent_id: str,
        order: EvidenceOrder,
    ) -> None:
        attempts, _malformed = self.attempts()
        for operation in attempts:
            if (
                operation.agent_id == agent_id
                and operation.identity is None
                and operation.order <= order
            ):
                self._unlink(operation.path)
