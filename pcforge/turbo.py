"""Turbo Boost: temporarily freeze non-essential background processes.

Suspended processes are only ever ones that (a) belong to you, (b) have no visible
window, (c) are not on the protected list and (d) match the chosen mode's list or
your own extras. State is saved to disk so `restore()` works even after a crash.
"""
from __future__ import annotations

import ctypes
import json
import os
import re
from ctypes import wintypes

import psutil

from .safety import data_dir, log_action

PROTECTED = re.compile(
    r"^(system|registry|smss|csrss|wininit|winlogon|services|lsass|lsaiso|svchost|dwm|explorer|fontdrvhost|"
    r"sihost|taskhostw|runtimebroker|shellexperiencehost|startmenuexperiencehost|searchhost|searchapp|ctfmon|"
    r"audiodg|conhost|dllhost|wudfhost|spoolsv|msmpeng|nissrv|securityhealth.*|sgrmbroker|memory compression|"
    r"textinputhost|applicationframehost|python|pythonw|py|code|claude|cmd|powershell|pwsh|windowsterminal|"
    r"nvcontainer|nvdisplay.container|rtkauduservice64|igfxem|igfxtray|hkcmd)$", re.I)

# Deliberately explicit: broad patterns like "helper" also match hardware/thermal helpers.
WORK_LIST = [r"updater$", r"^googleupdate", r"^msedgeupdate", r"^adobearm", r"^jusched", r"^googlecrashhandler",
             r"^creative cloud (ui )?helper", r"^adobe (desktop service|collaboration synchronizer)",
             r"^epicgameslauncher", r"^battle\.net", r"^eadesktop", r"^eabackgroundservice", r"^ubisoftconnect"]
GAME_LIST = WORK_LIST + [r"^onedrive", r"^dropbox", r"googledrivefs", r"^ms-teams", r"^teams", r"^slack", r"^skype",
                         r"^yourphone", r"^phoneexperiencehost", r"^widgets", r"^spotify"]
MODES = {"work": WORK_LIST, "game": GAME_LIST}


def _state_file():
    return data_dir() / "turbo_state.json"


def pids_with_visible_windows() -> set[int]:
    user32 = ctypes.windll.user32
    enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    pids: set[int] = set()

    def cb(hwnd, _lp):
        if user32.IsWindowVisible(hwnd) and user32.GetWindowTextLengthW(hwnd) > 0:
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pids.add(pid.value)
        return True

    user32.EnumWindows(enum_proc(cb), 0)
    return pids


SECURITY = re.compile(r"(defender|security|antivir|avast|avg|norton|mcafee|kaspersky|bitdefender|eset|malwarebytes|"
                      r"sophos|crowdstrike|sentinel|vpn|firewall)", re.I)


def _exe_dir(p: psutil.Process) -> str | None:
    try:
        return os.path.dirname(p.exe()).lower()
    except psutil.Error:
        return None


def candidates(mode: str = "work", extra: list[str] | None = None) -> list[psutil.Process]:
    pats = [re.compile(p, re.I) for p in MODES[mode] + (extra or [])]
    me = os.getpid()
    parents = {p.pid for p in psutil.Process(me).parents()}
    windowed = pids_with_visible_windows()
    # A helper that lives next to a program you have open is part of that program: leave it.
    open_app_dirs = set()
    for wp in windowed:
        try:
            d = _exe_dir(psutil.Process(wp))
        except psutil.Error:
            d = None
        if d:
            open_app_dirs.add(d)
    try:
        user = psutil.Process().username()
    except psutil.Error:
        user = None
    out = []
    for p in psutil.process_iter(["pid", "name", "username", "status"]):
        try:
            name = (p.info["name"] or "")
            stem = name[:-4] if name.lower().endswith(".exe") else name
            if p.info["pid"] in (me, 0, 4) or p.info["pid"] in parents or p.info["pid"] in windowed:
                continue
            if user and p.info["username"] != user:
                continue
            if p.info["status"] == psutil.STATUS_STOPPED or PROTECTED.match(stem) or SECURITY.search(stem):
                continue
            if any(rx.search(stem) for rx in pats):
                d = _exe_dir(p)
                if d is None or d in open_app_dirs or SECURITY.search(d):
                    continue  # can't verify what it belongs to -> don't touch
                out.append(p)
        except psutil.Error:
            continue
    return out


def enable(mode: str = "work", extra: list[str] | None = None, dry_run: bool = False) -> list[dict]:
    """Suspend the chosen processes. Returns what was (or would be) suspended."""
    done = []
    for p in candidates(mode, extra):
        try:
            rec = dict(pid=p.pid, name=p.name(), create_time=p.create_time())
            if not dry_run:
                p.suspend()
            done.append(rec)
        except psutil.Error:
            continue
    if not dry_run and done:
        existing = _load()
        _state_file().write_text(json.dumps(existing + done), encoding="utf-8")
        log_action("turbo-on", mode, count=len(done))
    return done


def _load() -> list[dict]:
    try:
        return json.loads(_state_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def restore() -> int:
    """Resume everything we suspended. Skips PIDs that were recycled by Windows."""
    resumed = 0
    for rec in _load():
        try:
            p = psutil.Process(rec["pid"])
            if abs(p.create_time() - rec["create_time"]) < 1:
                p.resume()
                resumed += 1
        except psutil.Error:
            continue
    try:
        _state_file().unlink()
    except OSError:
        pass
    log_action("turbo-off", "restore", count=resumed)
    return resumed


def active_count() -> int:
    return len(_load())
