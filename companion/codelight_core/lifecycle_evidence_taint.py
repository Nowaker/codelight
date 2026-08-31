from __future__ import annotations

import hashlib

from codelight_core.evidence_order import (
    INVENTORY_SCAN_FAILURE_OPERATION_PREFIX,
    EvidenceOrder,
)
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence_taint_io import (
    TaintDirectory,
    TaintOperation,
)


class GenerationTaintStore:
    def __init__(self, directory: str) -> None:
        self._files: TaintDirectory = TaintDirectory(directory)

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

    def mark(
        self,
        agent_id: str,
        identity: ProcessIdentity,
        scope_id: str,
        order: EvidenceOrder,
    ) -> TaintOperation:
        path = self._files.write(
            self._agent_prefix(agent_id),
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
        prefix = self._agent_prefix(agent_id)
        path = self._files.write(
            prefix,
            prefix,
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

    def attempts(self) -> tuple[tuple[TaintOperation, ...], bool]:
        operations, pending, malformed = self._files.inventory()
        return operations, malformed or bool(pending)

    def clear_success(self, operation: TaintOperation) -> None:
        self._files.unlink(operation.path)

    def clear_scope_through(
        self,
        agent_id: str,
        identity: ProcessIdentity,
        scope_id: str,
        order: EvidenceOrder,
    ) -> None:
        attempts, pending, _malformed = self._files.inventory()
        for candidate in attempts:
            if (
                candidate.agent_id == agent_id
                and self._same_identity(candidate.identity, identity)
                and candidate.scope_id == scope_id
                and candidate.order <= order
            ):
                self._files.unlink(candidate.path)
        prefix = self._prefix(
            agent_id,
            identity,
            scope_id,
        )
        for candidate in pending:
            if (
                candidate.marker_prefix == prefix
                and candidate.order <= order
            ):
                self._files.unlink(candidate.path)

    def has_agent_taint(self, agent_id: str) -> bool:
        attempts, malformed = self.attempts()
        return malformed or any(
            operation.agent_id == agent_id and operation.identity is None
            for operation in attempts
        )

    def clear_agent_before(
        self,
        agent_id: str,
        order: EvidenceOrder,
    ) -> None:
        attempts, pending, _malformed = self._files.inventory()
        for operation in attempts:
            if (
                operation.agent_id == agent_id
                and operation.identity is None
                and operation.order.token < order.token
            ):
                self._files.unlink(operation.path)
        prefix = self._agent_prefix(agent_id)
        for operation in pending:
            if (
                operation.agent_prefix == prefix
                and operation.order.token < order.token
            ):
                self._files.unlink(operation.path)

    def clear_inventory_scan_failures_before(
        self,
        agent_id: str,
        order: EvidenceOrder,
    ) -> None:
        attempts, pending, _malformed = self._files.inventory()
        for operation in attempts:
            if (
                operation.agent_id == agent_id
                and operation.identity is None
                and operation.order.token < order.token
                and operation.order.operation_id.startswith(
                    INVENTORY_SCAN_FAILURE_OPERATION_PREFIX
                )
            ):
                self._files.unlink(operation.path)
        prefix = self._agent_prefix(agent_id)
        for operation in pending:
            if (
                operation.agent_prefix == prefix
                and operation.marker_prefix == prefix
                and operation.order.token < order.token
                and operation.order.operation_id.startswith(
                    INVENTORY_SCAN_FAILURE_OPERATION_PREFIX
                )
            ):
                self._files.unlink(operation.path)
