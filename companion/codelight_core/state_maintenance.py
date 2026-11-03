"""Bounded upkeep of everything codelight keeps under ``monitor_state``.

Each pass, started detached by whichever process requests it:

- deletes previous-boot evidence stores beyond the retention policy;
- compacts the current boot's taint directory and drops scope evidence of
  process generations that no longer exist. Replay never matches that evidence
  to a live process; it only blocks generation admission, and left alone it
  grows with every reporter killed mid-write;
- deletes daemon-unavailable fallback session files nobody updated within the
  retention window. Codelight only writes them, so stale ones are dead weight.

One pass runs at a time per store, under an exclusive lock.
"""
from __future__ import annotations

import fcntl
import os
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from codelight_core.boot_epoch import (
    PREVIOUS_BOOT_MAX_AGE_SECONDS,
    claim_due_maintenance,
    prune_previous_boots,
)
from codelight_core.lifecycle_evidence_compaction import (
    GenerationAlive,
    _generation_alive,
    compact_taints,
)

MAINTENANCE_LOCK = 'maintenance.lock'
FALLBACK_STATE_MAX_AGE_SECONDS = PREVIOUS_BOOT_MAX_AGE_SECONDS


def prune_fallback_states(
    monitor_state_dir: str,
    *,
    max_age_seconds: float = FALLBACK_STATE_MAX_AGE_SECONDS,
    now: Callable[[], float] = time.time,
) -> int:
    cutoff = now() - max_age_seconds
    removed = 0
    try:
        entries = list(os.scandir(monitor_state_dir))
    except FileNotFoundError:
        return 0
    for entry in entries:
        if not entry.name.endswith('.json') or not entry.is_file(follow_symlinks=False):
            continue
        try:
            if entry.stat(follow_symlinks=False).st_mtime < cutoff:
                os.unlink(entry.path)
                removed += 1
        except FileNotFoundError:
            continue
    return removed


def maintain_state(
    legacy_path: str,
    monitor_state_dir: str,
    agent_ids: Iterable[str],
    *,
    generation_alive: GenerationAlive = _generation_alive,
    now: Callable[[], float] = time.time,
) -> dict[str, object]:
    root = Path(f'{legacy_path}.boots')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(root / MAINTENANCE_LOCK, 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'skipped': 'already running'}
        boots = prune_previous_boots(legacy_path, now=now)
        taints = root / str(boots['current']) / 'evidence.sqlite3.taints'
        compaction = (
            compact_taints(str(taints), agent_ids, drop_dead_generations=True,
                           generation_alive=generation_alive, now=now)
            if boots['current'] and taints.is_dir()
            else None
        )
        fallback_states_removed = prune_fallback_states(monitor_state_dir, now=now)
        claim_due_maintenance(legacy_path, interval_seconds=0, now=now)
    return {
        'boots': boots,
        'taints': compaction,
        'fallback-states-removed': fallback_states_removed,
    }
