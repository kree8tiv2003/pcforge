"""Plain-language history of what PCForge changed, and the undo actions behind it."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from . import hardening, registry_cleaner, turbo
from .safety import data_dir, fmt_size, log_action

_SENTENCES = {
    "delete": "Removed {n} file(s) or folder(s), freeing {freed}",
    "delete-partial": "Removed {n} folder(s) that were partly in use, freeing {freed}",
    "registry-delete": "Removed {n} registry entr{ies} (a backup was saved first)",
    "registry-restore": "Restored registry backup(s)",
    "registry-restore-point": "Asked Windows for a restore point",
    "restore-point": "Created a Windows restore point",
    "startup-disable": "Turned off {n} startup item(s)",
    "startup-enable": "Turned on {n} startup item(s)",
    "turbo-on": "Turbo Boost paused background programs",
    "turbo-off": "Turbo Boost woke the paused programs",
    "harden-firefox": "Applied tracking protection to Firefox",
    "harden-chromium": "Applied tracking protection to Chrome/Edge",
    "harden-revert": "Undid browser tracking protection",
    "quarantine": "Moved {n} suspicious file(s) to quarantine (can be restored)",
    "shred": "Permanently shredded {n} file(s)",
    "software-upgrade": "Updated {n} program(s)",
    "hosts-apply": "Turned on website blocking",
    "hosts-remove": "Turned off website blocking",
    "privacy-sweep": "Cleared browser and Windows traces",
}
_UNDOABLE = {"registry-delete", "startup-disable", "turbo-on", "harden-firefox", "harden-chromium", "quarantine"}


@dataclass
class HistoryRow:
    when: str
    text: str
    undoable: bool


def _read_log() -> list[dict]:
    p = data_dir() / "actions.log"
    if not p.exists():
        return []
    rows = []
    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rows.append(json.loads(ln))
        except ValueError:
            continue
    return rows


def recent_actions(limit: int = 60) -> list[HistoryRow]:
    """Group the raw log into one readable line per kind of action per minute (newest first)."""
    groups: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for r in _read_log():
        key = (r["t"][:16], r["kind"])
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"n": 0, "freed": 0}
            order.append(key)
        g["n"] += 1
        g["freed"] += int(r.get("freed", 0) or r.get("count", 0) * 0)
    out = []
    for when, kind in reversed(order):
        g = groups[(when, kind)]
        tmpl = _SENTENCES.get(kind, kind.replace("-", " ").capitalize())
        text = tmpl.format(n=g["n"], freed=fmt_size(g["freed"]), ies="y" if g["n"] == 1 else "ies")
        out.append(HistoryRow(when, text, kind in _UNDOABLE))
    return out[:limit]


# ----------------------------------------------------------------- undo helpers

def registry_backups() -> list[Path]:
    return list(reversed(registry_cleaner.list_backups()))


def undo_registry(folder: Path) -> int:
    return registry_cleaner.restore_backup(folder)


def quarantined() -> list[dict]:
    qdir = data_dir() / "quarantine"
    items = []
    if qdir.exists():
        for meta in sorted(qdir.glob("*.json")):
            try:
                original = json.loads(meta.read_text(encoding="utf-8"))["original"]
            except (OSError, ValueError, KeyError):
                continue
            blob = meta.with_suffix("")          # "<name>.quarantined"
            if blob.exists():
                items.append({"blob": blob, "meta": meta, "original": original})
    return items


def restore_quarantined(item: dict) -> bool:
    dest = Path(item["original"])
    if dest.exists():
        return False                              # never overwrite something that is there now
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(item["blob"], dest)
        item["meta"].unlink(missing_ok=True)
    except OSError:
        return False
    log_action("quarantine-restore", str(dest))
    return True


def browser_backups() -> list[Path]:
    root = data_dir() / "browser-backups"
    return sorted((p for p in root.glob("*") if (p / "manifest.json").exists()), reverse=True) if root.exists() else []


def restore_browser_backup(folder: Path) -> tuple[int, list[str]]:
    """Put back files a Privacy Sweep removed. Refuses while a browser is open. Whatever the browser has
    created in the meantime is kept next to the file as '<name>.before-restore'."""
    from . import privacy
    busy = [n for n, (_r, proc) in privacy.CHROMIUM.items() if privacy._running(proc)]
    if privacy._running("firefox.exe"):
        busy.append("Firefox")
    if busy:
        return 0, [f"close {', '.join(busy)} first"]
    restored, problems = 0, []
    for e in json.loads((Path(folder) / "manifest.json").read_text(encoding="utf-8")):
        src, dst = Path(e["backup"]), Path(e["original"])
        try:
            if dst.exists():
                aside = dst.with_name(dst.name + ".before-restore")
                if aside.exists():
                    shutil.rmtree(aside) if aside.is_dir() else aside.unlink()
                dst.rename(aside)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src, dst) if src.is_dir() else shutil.copy2(src, dst)
            restored += 1
        except OSError as ex:
            problems.append(f"{dst.name}: {ex}")
    log_action("browser-restore", str(folder), files=restored)
    return restored, problems


def undo_turbo() -> int:
    return turbo.restore()


def undo_hardening() -> dict:
    return hardening.revert()
