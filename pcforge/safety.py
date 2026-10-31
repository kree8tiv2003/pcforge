"""Shared plumbing: findings, safe deletion, logging, admin check.

Every destructive operation in PCForge goes through here so the rules live in one
place: nothing outside an allowed root is touched, links are never followed, and
every action is appended to a log.
"""
from __future__ import annotations

import ctypes
import json
import os
import shutil
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import brand


def data_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    d = base / brand.DATA_FOLDER
    d.mkdir(parents=True, exist_ok=True)
    return d


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


@dataclass
class Finding:
    category: str
    label: str
    path: str = ""
    size: int = 0
    risk: str = "low"          # low | medium | high
    selected: bool = True      # pre-ticked in the UI / included by AI mode
    needs_admin: bool = False
    meta: dict = field(default_factory=dict)


def log_action(kind: str, detail: str, **extra) -> None:
    rec = {"t": time.strftime("%Y-%m-%d %H:%M:%S"), "kind": kind, "detail": detail, **extra}
    try:
        with open(data_dir() / "actions.log", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


# ------------------------------------------------------------- ignore list

def _ignore_file() -> Path:
    return data_dir() / "ignore.json"


def load_ignore() -> list[str]:
    try:
        return json.loads(_ignore_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def add_ignore(item: str) -> None:
    items = load_ignore()
    if item.lower() not in [i.lower() for i in items]:
        items.append(item)
        _ignore_file().write_text(json.dumps(items, indent=1), encoding="utf-8")


def remove_ignore(item: str) -> None:
    items = [i for i in load_ignore() if i.lower() != item.lower()]
    _ignore_file().write_text(json.dumps(items, indent=1), encoding="utf-8")


def filter_ignored(findings: list[Finding]) -> list[Finding]:
    """Drop findings whose path (or any parent folder / registry key) is on the ignore list."""
    ign = [i.lower().rstrip("\\") for i in load_ignore()]
    if not ign:
        return findings
    keep = []
    for f in findings:
        p = f.path.lower()
        if not any(p == i or p.startswith(i + "\\") or p.startswith(i + " ") for i in ign):
            keep.append(f)
    return keep


# ----------------------------------------------------------- restore point

def create_restore_point(description: str = f"{brand.NAME} before changes") -> tuple[bool, str]:
    """Ask Windows for a System Restore point. Needs admin; Windows allows one per 24 h by default."""
    if not is_admin():
        return False, "needs administrator"
    import subprocess
    ps = f"Checkpoint-Computer -Description '{description}' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop"
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                       creationflags=0x08000000)
    ok = r.returncode == 0
    log_action("restore-point", description, ok=ok)
    return ok, (r.stderr.strip().splitlines() or ["created"])[0] if not ok else "created"


# ---------------------------------------------------------------- filesystem

_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def is_link(path: str | os.PathLike) -> bool:
    """True for symlinks and junctions; we never descend into or delete through them."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE)


def tree_size(path: str | os.PathLike) -> int:
    """Total bytes under path without following links. Errors are ignored."""
    try:
        if not os.path.isdir(path) or is_link(path):
            return os.lstat(path).st_size
    except OSError:
        return 0
    total = 0
    stack = [str(path)]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_symlink() or is_link(e.path):
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return path != root
    except ValueError:
        return False


def delete_path(path: str, allowed_roots: list[str], dry_run: bool = True) -> tuple[int, str | None]:
    """Delete a file or folder if it sits strictly inside one of allowed_roots.

    Returns (bytes_freed, error). A link is removed as a link, never followed.
    In dry-run mode nothing is touched but the size is still reported.
    """
    p = Path(os.path.normpath(path))
    roots = [Path(os.path.normpath(r)) for r in allowed_roots]
    if not any(_under(p, r) for r in roots):
        return 0, "outside allowed roots"
    if not os.path.lexists(p):
        return 0, "already gone"
    size = tree_size(p)
    if dry_run:
        return size, None
    try:
        if is_link(p) or p.is_file():
            os.chmod(p, stat.S_IWRITE) if not is_link(p) else None
            p.unlink()
        else:
            shutil.rmtree(p, onerror=_force_remove)
            if p.exists():
                # partially removed (locked files): report what actually went
                size = max(0, size - tree_size(p))
                log_action("delete-partial", str(p), freed=size)
                return size, "some files in use"
        log_action("delete", str(p), freed=size)
        return size, None
    except PermissionError:
        return 0, "in use or access denied"
    except OSError as e:
        return 0, str(e)


def _force_remove(func, path, exc_info):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


@dataclass
class CleanResult:
    freed: int = 0
    removed: int = 0
    skipped: list = field(default_factory=list)   # (path, reason)

    def add(self, path: str, freed: int, err: str | None):
        if err and not freed:
            self.skipped.append((path, err))
        else:
            self.freed += freed
            self.removed += 1
            if err:
                self.skipped.append((path, err))
