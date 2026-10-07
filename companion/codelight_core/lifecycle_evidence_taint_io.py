from __future__ import annotations

import json
import hashlib
import os
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import cast

from codelight_core.evidence_order import (
    INVENTORY_SCAN_FAILURE_OPERATION_PREFIX,
    EvidenceOrder,
)
from codelight_core.boot_epoch import available_boot_identity
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_pending_taint import (
    PendingTaint,
    looks_like_pending_taint,
    parse_pending_taint,
)


# Scope markers live in SCOPE_CONTAINER/<scope prefix>/ so a reporter clearing
# its own scope lists only that directory. The container name ends in ".taint"
# on purpose: a reader that predates this layout tries to parse it as a marker,
# fails, and treats the inventory as malformed instead of silently skipping it.
SCOPE_CONTAINER = "scopes.taint"
# Present once no scope marker remains at the top level, so scope cleanup can
# stop listing the top level. Written only by compaction.
SCOPE_LAYOUT_MARKER = "scopes.layout"
TRANSPORT_FAILURE_MARKER_SUFFIX = "-00000000000000000000-1-transport-failed.taint"


@dataclass(frozen=True, slots=True)
class TaintOperation:
    agent_id: str
    identity: ProcessIdentity | None
    scope_id: str | None
    order: EvidenceOrder
    path: str


@dataclass(frozen=True, slots=True)
class UnorderedFailure:
    agent_id: str
    path: str


class InvalidTaintMarkerError(ValueError):
    pass


def agent_marker_prefix(agent_id: str) -> str:
    return hashlib.sha256(f"agent\0{agent_id}".encode()).hexdigest()


def dominated_agent_markers(
    operations: tuple[TaintOperation, ...] | list[TaintOperation],
) -> list[TaintOperation]:
    """Agent markers below the newest one of their agent and cleanup family.

    Every reader takes the maximum agent order, and cleanup removes agent
    markers strictly older than a token, so only the maximum can matter.
    Inventory-scan failures are a separate family because their own cleanup
    removes them without touching other agent markers.
    """
    newest: dict[tuple[str, bool], TaintOperation] = {}
    for operation in operations:
        if operation.identity is not None:
            continue
        key = (
            operation.agent_id,
            operation.order.operation_id.startswith(INVENTORY_SCAN_FAILURE_OPERATION_PREFIX),
        )
        current = newest.get(key)
        if current is None or operation.order > current.order:
            newest[key] = operation
    kept = {id(operation) for operation in newest.values()}
    return [
        operation for operation in operations
        if operation.identity is None and id(operation) not in kept
    ]


class TaintDirectory:
    def __init__(self, directory: str) -> None:
        self._directory: str = directory
        self._scopes: str = os.path.join(directory, SCOPE_CONTAINER)
        self._boot_id = available_boot_identity()

    def _ensure_directory(self) -> None:
        os.makedirs(self._directory, mode=0o700, exist_ok=True)
        os.chmod(self._directory, 0o700)

    def _ensure_scope_directory(self, scope_prefix: str) -> str:
        # No fsync of the parents: taints are boot-scoped, so only an OS crash
        # could lose these entries, and that crash retires this boot's store.
        self._ensure_directory()
        path = os.path.join(self._scopes, scope_prefix)
        os.makedirs(path, mode=0o700, exist_ok=True)
        return path

    @staticmethod
    def _fsync_directory(path: str) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

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
        *,
        scoped: bool = False,
    ) -> str:
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        if scoped:
            directory = self._ensure_scope_directory(marker_prefix)
        else:
            self._ensure_directory()
            directory = self._directory
        marker_name = (
            f"{marker_prefix}-{order.token:020d}-{order.authority_rank}-"
            f"{order.operation_id}.taint"
        )
        marker_path = os.path.join(directory, marker_name)
        descriptor, temporary_path = tempfile.mkstemp(
            dir=directory,
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
            self._fsync_directory(directory)
            published = True
        finally:
            if not published:
                self.unlink(temporary_path)
        return marker_path

    @staticmethod
    def _claim(path: str) -> str:
        # Renaming the coalesced failure marker away before any order token is
        # taken lets the next failure write a fresh one instead of relying on a
        # barrier that may already be older than it.
        claimed = f"{path.removesuffix('.taint')}-{uuid.uuid4()}.taint"
        os.rename(path, claimed)
        return claimed

    def _parse(self, path: str) -> TaintOperation | UnorderedFailure:
        if os.path.basename(path).endswith(TRANSPORT_FAILURE_MARKER_SUFFIX):
            path = self._claim(path)
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
            _ = uuid.UUID(operation_id.removeprefix("transport-failed-"))
            return UnorderedFailure(agent_id, path)
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
        identity = ProcessIdentity(pid, ppid, generation, executable, executable, self._boot_id)
        return TaintOperation(agent_id, identity, scope_id, order, path)

    def _promote(self, unordered: list[UnorderedFailure]) -> list[TaintOperation]:
        """Give every unordered failure seen by one scan a single barrier.

        Bun's hrtime is process-relative, so the reader assigns the order in
        the authority clock. Each failure happened before its marker was
        listed, so one token taken after the listing covers all of them. The
        ordered marker is durable before the unordered ones are removed; a
        crash in between only delays recovery.
        """
        promoted = []
        by_agent: dict[str, list[str]] = {}
        for failure in unordered:
            by_agent.setdefault(failure.agent_id, []).append(failure.path)
        for agent_id, paths in sorted(by_agent.items()):
            order = EvidenceOrder(time.monotonic_ns(), 1, f"transport-failed-{uuid.uuid4()}")
            prefix = agent_marker_prefix(agent_id)
            materialized = self.write(prefix, prefix, {
                "kind": "agent", "agent_id": agent_id,
                "order_token": order.token, "authority_rank": 1,
                "operation_id": order.operation_id,
            }, order)
            for path in paths:
                self.unlink(path)
            promoted.append(TaintOperation(agent_id, None, None, order, materialized))
        return promoted

    @staticmethod
    def _marker_entries(directory: str) -> list[tuple[str, str]]:
        with os.scandir(directory) as entries:
            return [
                (entry.path, entry.name)
                for entry in entries
                if (entry.name.endswith(".taint") and entry.name != SCOPE_CONTAINER)
                or looks_like_pending_taint(entry.name)
            ]

    def _scope_entries(self, scope_prefix: str | None) -> tuple[list[tuple[str, str]], bool]:
        if scope_prefix is not None:
            try:
                return self._marker_entries(os.path.join(self._scopes, scope_prefix)), False
            except FileNotFoundError:
                return [], False
        try:
            with os.scandir(self._scopes) as entries:
                directories = [(entry.path, entry.is_dir(follow_symlinks=False)) for entry in entries]
        except FileNotFoundError:
            return [], False
        paths: list[tuple[str, str]] = []
        malformed = False
        for path, is_directory in directories:
            if not is_directory:
                malformed = True
                continue
            try:
                paths.extend(self._marker_entries(path))
            except FileNotFoundError:
                continue
        return paths, malformed

    def _listing(
        self,
        *,
        inventory_failures_only: bool,
        scope_prefix: str | None,
    ) -> tuple[list[tuple[str, str]], bool]:
        if scope_prefix is not None and os.path.exists(
            os.path.join(self._directory, SCOPE_LAYOUT_MARKER)
        ):
            return self._scope_entries(scope_prefix)
        paths = [
            (path, name)
            for path, name in self._marker_entries(self._directory)
            if not (inventory_failures_only and "-inventory-scan-failed-" not in name)
            and not (scope_prefix is not None and not (
                name.startswith(scope_prefix + "-")
                or (name.startswith(".") and f".{scope_prefix}-" in name)
            ))
        ]
        if inventory_failures_only:
            return paths, False
        scoped, malformed = self._scope_entries(scope_prefix)
        return paths + scoped, malformed

    def inventory(
        self,
        *,
        retry_missing: bool = True,
        inventory_failures_only: bool = False,
        scope_prefix: str | None = None,
    ) -> tuple[tuple[TaintOperation, ...], tuple[PendingTaint, ...], bool]:
        try:
            paths, malformed = self._listing(
                inventory_failures_only=inventory_failures_only,
                scope_prefix=scope_prefix,
            )
        except FileNotFoundError:
            return (), (), False
        operations: list[TaintOperation] = []
        unordered: list[UnorderedFailure] = []
        pending: list[PendingTaint] = []
        for path, name in paths:
            try:
                if name.endswith(".taint"):
                    parsed = self._parse(path)
                    if isinstance(parsed, UnorderedFailure):
                        unordered.append(parsed)
                    else:
                        operations.append(parsed)
                else:
                    pending.append(parse_pending_taint(path))
            except FileNotFoundError:
                if retry_missing:
                    fresh_operations, fresh_pending, fresh_malformed = self.inventory(
                        retry_missing=False, inventory_failures_only=inventory_failures_only,
                        scope_prefix=scope_prefix)
                    return fresh_operations, fresh_pending, malformed or bool(pending) or fresh_malformed
                malformed = True
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                malformed = True
        if unordered:
            operations.extend(self._promote(unordered))
        if scope_prefix is None and not inventory_failures_only:
            dominated = dominated_agent_markers(operations)
            for operation in dominated:
                self.unlink(operation.path)
            removed = {id(operation) for operation in dominated}
            operations = [operation for operation in operations if id(operation) not in removed]
        return tuple(operations), tuple(pending), malformed

    def has_pending(self) -> bool:
        try:
            with os.scandir(self._directory) as entries:
                if any(looks_like_pending_taint(entry.name) for entry in entries):
                    return True
        except FileNotFoundError:
            return False
        scoped, _malformed = self._scope_entries(None)
        return any(not name.endswith(".taint") for _path, name in scoped)
