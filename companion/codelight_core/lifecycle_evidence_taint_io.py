from __future__ import annotations

import json
import hashlib
import os
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import cast

from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_pending_taint import (
    PendingTaint,
    looks_like_pending_taint,
    parse_pending_taint,
)


@dataclass(frozen=True, slots=True)
class TaintOperation:
    agent_id: str
    identity: ProcessIdentity | None
    scope_id: str | None
    order: EvidenceOrder
    path: str


class InvalidTaintMarkerError(ValueError):
    pass


class TaintDirectory:
    def __init__(self, directory: str) -> None:
        self._directory: str = directory

    def _ensure_directory(self) -> None:
        os.makedirs(self._directory, mode=0o700, exist_ok=True)
        os.chmod(self._directory, 0o700)

    @staticmethod
    def unlink(path: str) -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            return

    def write(
        self,
        agent_prefix: str,
        marker_prefix: str,
        payload: dict[str, str | int | None],
        order: EvidenceOrder,
    ) -> str:
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        self._ensure_directory()
        marker_name = (
            f"{marker_prefix}-{order.token:020d}-{order.authority_rank}-"
            f"{order.operation_id}.taint"
        )
        marker_path = os.path.join(self._directory, marker_name)
        descriptor, temporary_path = tempfile.mkstemp(
            dir=self._directory,
            prefix=f".{agent_prefix}.{marker_name}.",
            suffix=".tmp",
        )
        published = False
        try:
            try:
                written = 0
                while written < len(encoded):
                    written += os.write(descriptor, encoded[written:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary_path, marker_path)
            directory = os.open(self._directory, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            published = True
        finally:
            if not published:
                self.unlink(temporary_path)
        return marker_path

    def _parse(self, path: str) -> TaintOperation:
        with open(path, encoding="utf-8") as marker:
            raw_payload = cast(object, json.load(marker))
        if not isinstance(raw_payload, dict):
            raise InvalidTaintMarkerError
        raw_mapping = cast(dict[object, object], raw_payload)
        payload: dict[str, object] = {
            key: value
            for key, value in raw_mapping.items()
            if isinstance(key, str)
        }
        agent_id = payload.get("agent_id")
        operation_id = payload.get("operation_id")
        token = payload.get("order_token")
        rank = payload.get("authority_rank")
        if (
            payload.get("kind") == "agent" and token is None and rank == 1
            and not isinstance(rank, bool)
            and isinstance(agent_id, str) and bool(agent_id)
            and isinstance(operation_id, str) and operation_id.startswith("transport-failed-")
        ):
            # Bun's hrtime is process-relative. Materialize the barrier once in
            # the authority clock; a crash before removal only delays recovery.
            operation = "transport-failed-" + str(uuid.UUID(operation_id.removeprefix("transport-failed-")))
            order = EvidenceOrder(time.monotonic_ns(), 1, operation)
            prefix = hashlib.sha256(f"agent\0{agent_id}".encode()).hexdigest()
            materialized = self.write(prefix, prefix, {
                "kind": "agent", "agent_id": agent_id,
                "order_token": order.token, "authority_rank": 1,
                "operation_id": operation,
            }, order)
            self.unlink(path)
            return TaintOperation(agent_id, None, None, order, materialized)
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

    def inventory(
        self,
        *,
        retry_missing: bool = True,
    ) -> tuple[tuple[TaintOperation, ...], tuple[PendingTaint, ...], bool]:
        try:
            with os.scandir(self._directory) as entries:
                paths = tuple(
                    (entry.path, entry.name)
                    for entry in entries
                    if entry.name.endswith(".taint")
                    or looks_like_pending_taint(entry.name)
                )
        except FileNotFoundError:
            return (), (), False
        operations: list[TaintOperation] = []
        pending: list[PendingTaint] = []
        malformed = False
        for path, name in paths:
            try:
                if name.endswith(".taint"):
                    operations.append(self._parse(path))
                else:
                    pending.append(parse_pending_taint(path))
            except FileNotFoundError:
                if retry_missing:
                    return self.inventory(retry_missing=False)
                malformed = True
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                malformed = True
        return tuple(operations), tuple(pending), malformed
