from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Callable


class _ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def _linux_generation(pid: int, read_text: Callable[[str], str]) -> str | None:
    try:
        boot_id = read_text("/proc/sys/kernel/random/boot_id").strip()
        stat = read_text(f"/proc/{pid}/stat")
    except OSError:
        return None
    closing_parenthesis = stat.rfind(")")
    if not boot_id or closing_parenthesis < 0:
        return None
    fields = stat[closing_parenthesis + 1:].split()
    if len(fields) <= 19 or not fields[19].isdigit():
        return None
    return f"linux:{boot_id}:{fields[19]}"


def _darwin_generation(pid: int) -> str | None:
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    except OSError:
        return None
    proc_pidinfo = library.proc_pidinfo
    proc_pidinfo.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    proc_pidinfo.restype = ctypes.c_int
    info = _ProcBsdInfo()
    size = ctypes.sizeof(info)
    written = proc_pidinfo(pid, 3, 0, ctypes.byref(info), size)
    if written != size or info.pbi_start_tvsec == 0:
        return None
    return f"darwin:{info.pbi_start_tvsec}:{info.pbi_start_tvusec}"


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def process_generation(pid: int, platform: str = sys.platform) -> str | None:
    if platform.startswith("linux"):
        return _linux_generation(pid, _read_text)
    if platform == "darwin":
        return _darwin_generation(pid)
    return None


def current_process_generation() -> str | None:
    return process_generation(os.getpid())
