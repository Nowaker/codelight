"""One-time, idempotent compaction of a boot-scoped taint directory.

Every step either does what a reader or writer would eventually do anyway, or
replaces evidence with stricter evidence:

- an interrupted write whose content is complete is finished as written;
- an interrupted agent-wide write is replaced by a fresh agent barrier;
- top-level scope markers move into the per-scope layout, after which scope
  cleanup lists only its own directory;
- unordered transport failures are promoted and dominated agent markers are
  pruned by an ordinary full inventory.

Only ``drop_dead_generations`` discards evidence: scope markers, and pending
scope writes attributable to them, whose process generation no longer exists.
Replay never matches them against a live process, but every such marker blocks
generation admission for its agent, so dropping them is a policy choice the
caller makes explicitly. Interrupted scope writes that cannot be attributed are
kept and still fail closed.
"""
from __future__ import annotations

import collections
import json
import os
import time
import uuid
from collections.abc import Callable, Iterable

from codelight_core import process_generation
from codelight_core.evidence_order import EvidenceOrder
from codelight_core.lifecycle_evidence_pending_taint import (
    InvalidPendingTaintError,
    looks_like_pending_taint,
    parse_pending_taint,
)
from codelight_core.lifecycle_evidence_taint_io import (
    SCOPE_CONTAINER,
    SCOPE_LAYOUT_MARKER,
    TaintDirectory,
    agent_marker_prefix,
)

GenerationAlive = Callable[[int, str], bool]


def _generation_alive(pid: int, generation: str) -> bool:
    return process_generation.process_generation(pid) == generation


def _read_json(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _scope_generation(payload: dict | None) -> tuple[int, str] | None:
    if payload is None or payload.get("kind") != "scope":
        return None
    pid, generation = payload.get("pid"), payload.get("generation")
    if isinstance(pid, int) and not isinstance(pid, bool) and isinstance(generation, str):
        return pid, generation
    return None


def count_entries(directory: str) -> dict[str, int]:
    counts: collections.Counter[str] = collections.Counter()
    for root, _directories, names in os.walk(directory):
        nested = root != directory
        for name in names:
            if looks_like_pending_taint(name):
                counts["pending-scoped" if nested else "pending-top-level"] += 1
            elif name.endswith(".taint"):
                counts["markers-scoped" if nested else "markers-top-level"] += 1
            else:
                counts["other"] += 1
    return dict(counts)


def compact_taints(
    directory: str,
    agent_ids: Iterable[str],
    *,
    drop_dead_generations: bool = False,
    min_age_seconds: float = 60.0,
    generation_alive: GenerationAlive = _generation_alive,
    now: Callable[[], float] = time.time,
) -> dict[str, object]:
    files = TaintDirectory(directory)
    agents = {agent_marker_prefix(agent_id): agent_id for agent_id in agent_ids}
    stats: collections.Counter[str] = collections.Counter()
    before = count_entries(directory)
    cutoff = now() - min_age_seconds
    alive_cache: dict[tuple[int, str], bool] = {}

    def alive(key: tuple[int, str]) -> bool:
        if key not in alive_cache:
            alive_cache[key] = generation_alive(*key)
        return alive_cache[key]

    def settled(path: str) -> bool:
        try:
            return os.stat(path).st_mtime < cutoff
        except FileNotFoundError:
            return False

    def scope_directory(prefix: str) -> str:
        path = os.path.join(directory, SCOPE_CONTAINER, prefix)
        os.makedirs(path, mode=0o700, exist_ok=True)
        return path

    def move(path: str, target_directory: str, name: str) -> None:
        try:
            os.rename(path, os.path.join(target_directory, name))
        except FileNotFoundError:
            stats["raced"] += 1

    def remove(path: str, stat: str) -> None:
        files.unlink(path)
        stats[stat] += 1

    try:
        with os.scandir(directory) as entries:
            top_level = [(entry.path, entry.name) for entry in entries if entry.is_file(follow_symlinks=False)]
    except FileNotFoundError:
        return {"before": before, "after": before, "actions": {}}

    scope_generations: dict[str, tuple[int, str]] = {}
    scope_markers: list[tuple[str, str, tuple[int, str] | None]] = []
    for path, name in top_level:
        if not name.endswith(".taint") or name[:64] in agents:
            continue
        generation = _scope_generation(_read_json(path))
        if generation is None:
            stats["kept-unrecognized-marker"] += 1
            continue
        scope_generations[name[:64]] = generation
        scope_markers.append((path, name, generation))
    for root, _directories, names in os.walk(os.path.join(directory, SCOPE_CONTAINER)):
        for name in names:
            if not name.endswith(".taint"):
                continue
            generation = _scope_generation(_read_json(os.path.join(root, name)))
            if generation is not None:
                scope_generations[name[:64]] = generation
                scope_markers.append((os.path.join(root, name), name, generation))

    def dead(generation: tuple[int, str] | None) -> bool:
        return drop_dead_generations and generation is not None and not alive(generation)

    for path, name in top_level:
        if not looks_like_pending_taint(name) or not settled(path):
            continue
        try:
            pending = parse_pending_taint(path)
        except InvalidPendingTaintError:
            stats["kept-unrecognized-pending"] += 1
            continue
        payload = _read_json(path)
        if pending.agent_prefix == pending.marker_prefix:
            agent_id = agents.get(pending.agent_prefix)
            if agent_id is None:
                stats["kept-pending-unknown-agent"] += 1
            elif payload is not None and payload.get("agent_id") == agent_id:
                token = payload.get("order_token")
                operation = payload.get("operation_id")
                suffix = f"{(token if isinstance(token, int) else 0):020d}-{payload.get('authority_rank')}-{operation}"
                move(path, directory, f"{pending.agent_prefix}-{suffix}.taint")
                stats["finished-pending-agent"] += 1
            else:
                order = EvidenceOrder(time.monotonic_ns(), 1, f"interrupted-agent-write-{uuid.uuid4()}")
                files.write(pending.agent_prefix, pending.agent_prefix, {
                    "kind": "agent", "agent_id": agent_id, "pid": None, "ppid": None,
                    "generation": None, "executable": None, "scope_id": None,
                    "order_token": order.token, "authority_rank": order.authority_rank,
                    "operation_id": order.operation_id,
                }, order)
                remove(path, "replaced-partial-pending-agent")
            continue
        generation = _scope_generation(payload) or scope_generations.get(pending.marker_prefix)
        if dead(generation):
            remove(path, "dropped-pending-dead-generation")
        elif payload is not None and _scope_generation(payload) is not None:
            order = pending.order
            move(path, scope_directory(pending.marker_prefix),
                 f"{pending.marker_prefix}-{order.token:020d}-{order.authority_rank}-{order.operation_id}.taint")
            stats["finished-pending-scope"] += 1
        else:
            move(path, scope_directory(pending.marker_prefix), name)
            stats["kept-partial-pending-scope"] += 1

    for path, name, generation in scope_markers:
        if dead(generation) and settled(path):
            remove(path, "dropped-scope-dead-generation")
        elif os.path.dirname(path) == directory:
            move(path, scope_directory(name[:64]), name)
            stats["migrated-scope-marker"] += 1

    _operations, _pending, malformed = files.inventory()
    stats["inventory-malformed"] = int(malformed)
    top_level_scope_left = any(
        name.endswith(".taint") and name[:64] not in agents and name != SCOPE_CONTAINER
        for name in os.listdir(directory)
    ) or any(
        looks_like_pending_taint(name) and name[1:65] != name[66:130]
        for name in os.listdir(directory)
    )
    layout = os.path.join(directory, SCOPE_LAYOUT_MARKER)
    if not top_level_scope_left and not os.path.exists(layout):
        with open(layout, "w", encoding="utf-8"):
            pass
        TaintDirectory._fsync_directory(directory)
        stats["wrote-layout-marker"] = 1
    return {
        "before": before,
        "after": count_entries(directory),
        "layout": os.path.exists(layout),
        "actions": dict(stats),
    }
