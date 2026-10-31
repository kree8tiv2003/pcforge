"""Toolbox: Large File Finder, File Shredder, Internet Booster, Software Updater, Win Fix."""
from __future__ import annotations

import heapq
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import time

from .safety import is_link, log_action

NO_WINDOW = 0x08000000


# ------------------------------------------------------- Large File Finder

def find_large_files(roots: list[str], min_mb: int = 100, top: int = 50) -> list[tuple[int, str]]:
    heap: list[tuple[int, str]] = []
    floor = min_mb * 1024 * 1024
    for root in roots:
        for dp, dn, files in os.walk(root, onerror=lambda e: None):
            dn[:] = [d for d in dn if not is_link(os.path.join(dp, d))]
            for fn in files:
                p = os.path.join(dp, fn)
                try:
                    size = os.lstat(p).st_size
                except OSError:
                    continue
                if size >= floor:
                    if len(heap) < top:
                        heapq.heappush(heap, (size, p))
                    elif size > heap[0][0]:
                        heapq.heapreplace(heap, (size, p))
    return sorted(heap, reverse=True)


# ------------------------------------------------------------ File Shredder

def shred_file(path: str, passes: int = 3, dry_run: bool = True) -> bool:
    """Overwrite with random data, rename, delete.

    Caveat shown in the UI: on SSDs and journaling/copy-on-write volumes the old
    blocks may survive wear levelling, so full-disk encryption is the stronger option.
    """
    if not os.path.isfile(path) or is_link(path):
        return False
    if dry_run:
        return True
    size = os.path.getsize(path)
    try:
        os.chmod(path, 0o666)
        with open(path, "r+b", buffering=0) as fh:
            for _ in range(passes):
                fh.seek(0)
                left = size
                while left > 0:
                    n = min(left, 1 << 20)
                    fh.write(secrets.token_bytes(n))
                    left -= n
                fh.flush()
                os.fsync(fh.fileno())
        new = os.path.join(os.path.dirname(path), secrets.token_hex(8))
        os.rename(path, new)
        os.remove(new)
    except OSError:
        return False
    log_action("shred", path, passes=passes)
    return True


def shred_folder(path: str, passes: int = 3, dry_run: bool = True) -> int:
    n = 0
    for dp, _dn, files in os.walk(path, topdown=False):
        for fn in files:
            n += shred_file(os.path.join(dp, fn), passes, dry_run)
        if not dry_run:
            try:
                os.rmdir(dp)
            except OSError:
                pass
    return n


# --------------------------------------------------------- Internet Booster

def flush_dns() -> bool:
    return subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=NO_WINDOW).returncode == 0


PUBLIC_DNS = {"Cloudflare": "1.1.1.1", "Google": "8.8.8.8", "Quad9": "9.9.9.9", "OpenDNS": "208.67.222.222"}


def _query_packet(name: str) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", secrets.randbits(16), 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)


def dns_benchmark(servers: dict[str, str] | None = None, rounds: int = 3, name: str = "example.com") -> list[tuple[str, str, float | None]]:
    """Median UDP round-trip (ms) per resolver. Read-only: changes no settings."""
    results = []
    for label, ip in (servers or PUBLIC_DNS).items():
        times = []
        for _ in range(rounds):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            try:
                t0 = time.perf_counter()
                s.sendto(_query_packet(name), (ip, 53))
                s.recv(512)
                times.append((time.perf_counter() - t0) * 1000)
            except OSError:
                pass
            finally:
                s.close()
        results.append((label, ip, sorted(times)[len(times) // 2] if times else None))
    return sorted(results, key=lambda r: (r[2] is None, r[2] or 0))


def tcp_settings() -> str:
    return subprocess.run(["netsh", "int", "tcp", "show", "global"], capture_output=True, text=True,
                          creationflags=NO_WINDOW).stdout


# --------------------------------------------------------- Software Updater

def winget_available() -> bool:
    return shutil.which("winget") is not None


def outdated_software() -> list[dict]:
    r = subprocess.run(["winget", "upgrade", "--accept-source-agreements"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", creationflags=NO_WINDOW)
    lines = [ln.rstrip() for ln in r.stdout.splitlines()]
    hdr = next((i for i, ln in enumerate(lines) if re.search(r"\bName\b.*\bId\b.*\bVersion\b", ln)), None)
    if hdr is None:
        return []
    h = lines[hdr]
    c_id, c_ver, c_av = h.index("Id"), h.index("Version"), h.index("Available")
    c_src = h.index("Source") if "Source" in h else len(h) + 200
    rows = []
    for ln in lines[hdr + 2:]:
        if not ln.strip() or re.match(r"^\d+ upgrades? available", ln):
            break
        rows.append(dict(name=ln[:c_id].strip(), id=ln[c_id:c_ver].strip(), version=ln[c_ver:c_av].strip(),
                         available=ln[c_av:c_src].strip()))
    return rows


def upgrade_software(app_id: str) -> bool:
    r = subprocess.run(["winget", "upgrade", "--id", app_id, "--silent", "--accept-package-agreements",
                        "--accept-source-agreements"], capture_output=True, creationflags=NO_WINDOW)
    log_action("software-upgrade", app_id, rc=r.returncode)
    return r.returncode == 0


# ------------------------------------------------------------------ Win Fix

def run_sfc() -> str:
    return subprocess.run(["sfc", "/scannow"], capture_output=True, text=True, errors="replace",
                          creationflags=NO_WINDOW).stdout.replace("\x00", "")


def dism_check() -> str:
    return subprocess.run(["DISM", "/Online", "/Cleanup-Image", "/CheckHealth"], capture_output=True, text=True,
                          errors="replace", creationflags=NO_WINDOW).stdout


def chkdsk_scan(drive: str = "C:") -> str:
    return subprocess.run(["chkdsk", drive, "/scan"], capture_output=True, text=True, errors="replace",
                          creationflags=NO_WINDOW).stdout


def disk_summary() -> list[dict]:
    import psutil
    out = []
    for p in psutil.disk_partitions(all=False):
        if "cdrom" in p.opts or not p.fstype:
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
            out.append(dict(drive=p.mountpoint, total=u.total, free=u.free, percent=u.percent))
        except OSError:
            pass
    return out
