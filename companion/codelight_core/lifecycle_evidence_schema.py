from __future__ import annotations

import os
import sqlite3


SCHEMA_VERSION = 4
DROP_STATEMENTS = (
    "DROP TABLE IF EXISTS session_evidence",
    "DROP TABLE IF EXISTS provider_evidence",
    "DROP TABLE IF EXISTS scope_invalidations",
    "DROP TABLE IF EXISTS agent_invalidations",
)
CREATE_STATEMENTS = (
    """
    CREATE TABLE provider_evidence (
        agent_id TEXT NOT NULL,
        pid INTEGER NOT NULL,
        ppid INTEGER NOT NULL,
        started_at TEXT NOT NULL,
        executable TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        observed_at REAL NOT NULL,
        order_token INTEGER NOT NULL,
        authority_rank INTEGER NOT NULL,
        operation_id TEXT NOT NULL,
        snapshot_order_token INTEGER NOT NULL,
        snapshot_authority_rank INTEGER NOT NULL,
        snapshot_operation_id TEXT NOT NULL,
        lease_deadline_ns INTEGER NOT NULL,
        complete INTEGER NOT NULL,
        PRIMARY KEY (agent_id, pid, started_at, scope_id)
    )
    """,
    """
    CREATE TABLE session_evidence (
        agent_id TEXT NOT NULL,
        pid INTEGER NOT NULL,
        started_at TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        state TEXT NOT NULL,
        observed_at REAL NOT NULL,
        order_token INTEGER NOT NULL,
        authority_rank INTEGER NOT NULL,
        operation_id TEXT NOT NULL,
        hook_event TEXT NOT NULL,
        PRIMARY KEY (agent_id, pid, started_at, scope_id, session_id)
    )
    """,
    """
    CREATE TABLE scope_invalidations (
        agent_id TEXT NOT NULL,
        pid INTEGER NOT NULL,
        started_at TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        order_token INTEGER NOT NULL,
        authority_rank INTEGER NOT NULL,
        operation_id TEXT NOT NULL,
        PRIMARY KEY (agent_id, pid, started_at, scope_id, operation_id)
    )
    """,
    """
    CREATE TABLE agent_invalidations (
        agent_id TEXT PRIMARY KEY,
        order_token INTEGER NOT NULL,
        authority_rank INTEGER NOT NULL,
        operation_id TEXT NOT NULL
    )
    """,
)


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != SCHEMA_VERSION:
            for statement in DROP_STATEMENTS:
                connection.execute(statement)
            for statement in CREATE_STATEMENTS:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        connection.commit()
    except (OSError, sqlite3.Error, TypeError, ValueError):
        connection.rollback()
        raise


def connect_evidence(path: str) -> sqlite3.Connection:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
        os.chmod(parent, 0o700)
    connection = sqlite3.connect(path, timeout=1.0)
    try:
        os.chmod(path, 0o600)
        connection.execute("PRAGMA busy_timeout = 1000")
        _initialize_schema(connection)
    except (OSError, sqlite3.Error):
        connection.close()
        raise
    return connection
