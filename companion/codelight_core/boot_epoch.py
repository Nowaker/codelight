from __future__ import annotations

import os
import subprocess
import sys
import tempfile
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
    def __init__(self, legacy_path: str) -> None:
        self.epoch: str | None = None
        self.path: str | None = None
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
                raise BootIdentityUnavailable('authority artifacts lack boot metadata')
            with tempfile.NamedTemporaryFile(mode='w', dir=directory, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(self.epoch)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                try:
                    os.link(temporary, metadata)
                except FileExistsError:
                    pass
            finally:
                temporary.unlink()
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if metadata.read_text() != self.epoch:
            raise BootIdentityUnavailable('authority boot metadata invalid')
        return self.path


def available_boot_identity() -> str:
    try:
        return boot_identity()
    except BootIdentityUnavailable:
        return ''
