import os
import sqlite3
import tempfile
import time
import unittest
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from unittest import mock

from codelight_core.evidence_order import (
    UNKNOWN_RANK,
    evidence_order,
    inventory_scan_failure_order,
)
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore, LifecycleReplay


@dataclass(frozen=True)
class PersistenceFixture:
    path: str
    store: LifecycleEvidenceStore
    identity: ProcessIdentity

    def record_idle(self, order_token: int) -> None:
        self.store.record_snapshot(
            agent_id="codex",
            identity=self.identity,
            sessions=(),
            complete=True,
            observed_at=time.time(),
            order_token=order_token,
            operation_id="known-idle",
        )

    def replay_inventory(self, order_token: int) -> LifecycleReplay:
        return self.store.replay_inventory(
            {"codex": frozenset({self.identity})},
            evidence_order(order_token, UNKNOWN_RANK, "successful-inventory"),
            now_order_token=order_token,
        )

    @contextmanager
    def force_sqlite_fallback(self) -> Iterator[None]:
        with mock.patch.object(
            self.store._taints,
            "mark_agent",
            side_effect=OSError("marker unavailable"),
        ):
            yield

    def operation_ids(self) -> tuple[str, ...]:
        with closing(self.store._connect()) as connection:
            return tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT operation_id FROM agent_invalidations "
                    "ORDER BY operation_id"
                )
            )


def persistence_fixture(tmp: str) -> PersistenceFixture:
    path = os.path.join(tmp, "evidence.sqlite3")
    return PersistenceFixture(
        path=path,
        store=LifecycleEvidenceStore(path),
        identity=ProcessIdentity(
            pid=100,
            ppid=1,
            started_at="darwin:1788076913:123456",
            executable="/opt/homebrew/bin/codex",
            command="/opt/homebrew/bin/codex",
        ),
    )


class InventoryInvalidationPersistenceTests(unittest.TestCase):
    def test_sqlite_fallback_clears_older_scan_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = persistence_fixture(tmp)
            fixture.record_idle(100)
            with fixture.force_sqlite_fallback():
                fixture.store.invalidate_inventory_scan_failure(
                    "codex", 200, "scan"
                )

            replay = fixture.replay_inventory(300)

            self.assertTrue(replay.providers[0].complete)
            self.assertEqual(fixture.operation_ids(), ())

    def test_sqlite_hook_survives_later_scan_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = persistence_fixture(tmp)
            fixture.record_idle(50)
            with fixture.force_sqlite_fallback():
                fixture.store.invalidate_agent("codex", 100, "unresolved-hook")
                fixture.store.invalidate_inventory_scan_failure(
                    "codex", 200, "scan"
                )

            replay = fixture.replay_inventory(300)

            self.assertFalse(replay.providers[0].complete)
            self.assertEqual(fixture.operation_ids(), ("unresolved-hook",))

    def test_sqlite_scan_and_later_hook_remain_independently_durable(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = persistence_fixture(tmp)
            fixture.record_idle(50)
            failure_order = inventory_scan_failure_order(100, "scan")
            with fixture.force_sqlite_fallback():
                fixture.store.invalidate_inventory_scan_failure(
                    "codex", failure_order.token, failure_order.operation_id
                )

                fixture.store.invalidate_agent("codex", 200, "unresolved-hook")

            self.assertEqual(
                fixture.operation_ids(),
                ("inventory-scan-failed-scan", "unresolved-hook"),
            )

            replay = fixture.replay_inventory(300)

            self.assertFalse(replay.providers[0].complete)
            self.assertEqual(fixture.operation_ids(), ("unresolved-hook",))

    def test_legacy_sqlite_invalidation_survives_successful_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = persistence_fixture(tmp)
            fixture.record_idle(50)
            with fixture.force_sqlite_fallback():
                fixture.store.invalidate_agent("codex", 100, "legacy-unknown")

            replay = fixture.replay_inventory(200)

            self.assertFalse(replay.providers[0].complete)
            self.assertEqual(fixture.operation_ids(), ("legacy-unknown",))

    def test_replay_folds_multiple_sqlite_invalidations_by_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = persistence_fixture(tmp)
            fixture.record_idle(50)
            with fixture.force_sqlite_fallback():
                fixture.store.invalidate_agent("codex", 200, "newer-hook")
                fixture.store.invalidate_agent("codex", 100, "older-hook")

            replay = fixture.store.replay(
                {"codex": frozenset({fixture.identity})},
                now_order_token=300,
            )[0]

            self.assertEqual(replay.order_token, 200)
            self.assertEqual(replay.operation_id, "newer-hook")


class AgentInvalidationMigrationTests(unittest.TestCase):
    def test_v4_row_is_preserved_and_v5_accepts_independent_operations(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "evidence.sqlite3")
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute(
                    """
                    CREATE TABLE agent_invalidations (
                        agent_id TEXT PRIMARY KEY,
                        order_token INTEGER NOT NULL,
                        authority_rank INTEGER NOT NULL,
                        operation_id TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO agent_invalidations VALUES (?, ?, ?, ?)",
                    ("codex", 100, UNKNOWN_RANK, "legacy-unknown"),
                )
                connection.execute("PRAGMA user_version = 4")

            store = LifecycleEvidenceStore(path)
            with closing(store._connect()) as connection, connection:
                connection.execute(
                    "INSERT INTO agent_invalidations VALUES (?, ?, ?, ?)",
                    ("codex", 200, UNKNOWN_RANK, "second-operation"),
                )
                version = int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                )
                operations = tuple(
                    str(row[0])
                    for row in connection.execute(
                        "SELECT operation_id FROM agent_invalidations "
                        "ORDER BY operation_id"
                    )
                )

        self.assertEqual(version, 5)
        self.assertEqual(operations, ("legacy-unknown", "second-operation"))


if __name__ == "__main__":
    unittest.main()
