from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from uuid import UUID


class BootIdentityUnavailable(OSError):
    pass


def boot_identity() -> str:
    try:
        match sys.platform:
            case 'linux':
                value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            case 'darwin':
                value = subprocess.run(
                    ['/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'],
                    capture_output=True, text=True, check=True, timeout=2,
                ).stdout.strip()
            case _:
                raise BootIdentityUnavailable('unsupported boot identity platform')
        return str(UUID(value))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise BootIdentityUnavailable('OS boot identity unavailable') from error


class BootPersistence:
    def __init__(self, legacy_path: str, on_new_epoch: Callable[[], None] | None = None) -> None:
        self.epoch: str | None = None
        self.path: str | None = None
        self._on_new_epoch = on_new_epoch
        try:
            self.epoch = boot_identity()
        except BootIdentityUnavailable:
            return
        self.path = str(Path(f'{legacy_path}.boots') / self.epoch / 'evidence.sqlite3')

    def verified_path(self) -> str:
        if self.epoch is None or self.path is None or boot_identity() != self.epoch:
            raise BootIdentityUnavailable('authority boot identity unavailable or changed')
        directory = Path(self.path).parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = directory / 'boot-id'
        # Publish a complete immutable identity without overwriting another writer.
        if not metadata.exists():
            if Path(self.path).exists() or Path(f'{self.path}.taints').exists():
                if not metadata.exists():
                    raise BootIdentityUnavailable('authority artifacts lack boot metadata')
            else:
                with tempfile.NamedTemporaryFile(mode='w', dir=directory, delete=False) as stream:
                    temporary = Path(stream.name)
                    stream.write(self.epoch)
                    stream.flush()
                    os.fsync(stream.fileno())
                published = False
                try:
                    try:
                        os.link(temporary, metadata)
                        published = True
                    except FileExistsError:
                        pass
                finally:
                    temporary.unlink()
                descriptor = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                # Exactly one process per boot publishes the metadata, which is
                # the moment the previous boot's store becomes history.
                if published and self._on_new_epoch is not None:
                    self._on_new_epoch()
        if metadata.read_text() != self.epoch:
            raise BootIdentityUnavailable('authority boot metadata invalid')
        return self.path


def available_boot_identity() -> str:
    try:
        return boot_identity()
    except BootIdentityUnavailable:
        return ''


PREVIOUS_BOOTS_KEPT = 2
PREVIOUS_BOOT_MAX_AGE_SECONDS = 7 * 24 * 3600
PRUNING_PREFIX = '.prune-'


def prune_previous_boots(
    legacy_path: str,
    *,
    keep: int = PREVIOUS_BOOTS_KEPT,
    max_age_seconds: float = PREVIOUS_BOOT_MAX_AGE_SECONDS,
    now: Callable[[], float] = time.time,
) -> dict[str, object]:
    """Delete previous-boot stores beyond the newest ``keep`` recently used ones.

    Previous boots are history only: no reader adopts them as authority. The
    current boot is never touched, and nothing is pruned when the current boot
    is unknown. Each victim is first renamed to a ``.prune-`` name, so a delete
    interrupted midway (the stores can hold millions of files) is finished by
    the next run instead of leaving a half-deleted boot that looks retained.
    """
    root = Path(f'{legacy_path}.boots')
    current = available_boot_identity()
    if not current:
        return {'current': None, 'kept': [], 'removed': [], 'failed': []}
    try:
        children = [entry for entry in root.iterdir() if entry.is_dir()]
    except FileNotFoundError:
        children = []

    def is_boot(name: str) -> bool:
        try:
            return str(UUID(name)) == name
        except ValueError:
            return False

    def last_used(directory: Path) -> float:
        database = directory / 'evidence.sqlite3'
        return max(directory.stat().st_mtime,
                   database.stat().st_mtime if database.exists() else 0.0)

    previous: list[tuple[float, Path]] = []
    for child in children:
        if child.name == current or not is_boot(child.name):
            continue
        try:
            previous.append((last_used(child), child))
        except FileNotFoundError:
            continue
    previous.sort(reverse=True)
    cutoff = now() - max_age_seconds
    kept = [child for used, child in previous[:keep] if used >= cutoff]
    victims = [child for _used, child in previous if child not in kept]
    doomed = [child for child in children if child.name.startswith(PRUNING_PREFIX)]
    for child in victims:
        target = root / f'{PRUNING_PREFIX}{child.name}'
        try:
            child.rename(target)
        except FileNotFoundError:
            continue
        doomed.append(target)
    removed: list[str] = []
    failed: list[str] = []
    for target in doomed:
        shutil.rmtree(target, ignore_errors=True)
        name = target.name.removeprefix(PRUNING_PREFIX)
        (failed if target.exists() else removed).append(name)
    return {
        'current': current,
        'kept': [child.name for child in kept],
        'removed': sorted(removed),
        'failed': sorted(failed),
    }
