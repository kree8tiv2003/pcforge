"""Startup optimizer covering Run keys, Startup folders, scheduled tasks and services.

Everything is reversible and nothing is deleted:
  - Run keys / Startup folders: Windows' own StartupApproved flag (same as Task Manager).
  - Scheduled tasks: Disable-/Enable-ScheduledTask.
  - Services: switch Automatic <-> Manual (the service stays installed and can still be started on demand).
"""
from __future__ import annotations

import json
import os
import re
import struct
import subprocess
import time
import winreg
from dataclasses import dataclass, field

from .registry_cleaner import command_exe
from .safety import is_admin, log_action

APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"

# Names that look like background helpers worth disabling vs things you want to keep.
_NONESSENTIAL = re.compile(r"(updat|helper|launcher|agent|assistant|sync|scheduler|checker|notifier|tray|quicktime|"
                           r"adobe.*(arm|gc)|jusched|spotify|steam|discord|onedrive|teams|skype)", re.I)
_KEEP = re.compile(r"(securit|defender|antivir|avast|norton|mcafee|kaspersky|bitdefender|eset|malwarebytes|realtek|"
                   r"nvidia|amd|intel|audio|touchpad|synaptics|bluetooth|wacom|ctfmon|ime|mouse|keyboard|trackpad|"
                   r"vpn|firewall|backup|driver|bitlocker|wacom)", re.I)


@dataclass
class StartupItem:
    name: str
    command: str
    source: str            # "HKCU Run", "HKLM Run", "Scheduled task", "Service", "Startup folder (...)"
    enabled: bool
    recommend_disable: bool
    needs_admin: bool
    kind: str = "run"      # run | folder | task | service
    _hive: int | None = None
    _view: int = 0
    _approved_sub: str = ""
    _task_path: str = ""
    _service: str = ""
    extra: dict = field(default_factory=dict)


def _approved_state(hive, sub, name) -> bool:
    try:
        with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ) as k:
            raw, _ = winreg.QueryValueEx(k, name)
            return not (isinstance(raw, bytes) and raw and raw[0] & 1)  # odd first byte == disabled
    except OSError:
        return True


def list_startup(include_tasks: bool = True, include_services: bool = True) -> list[StartupItem]:
    items: list[StartupItem] = []
    sources = [
        ("HKCU Run", winreg.HKEY_CURRENT_USER, 0, "Run", False),
        ("HKLM Run", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY, "Run", True),
        ("HKLM Run (32-bit)", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY, "Run32", True),
    ]
    for label, hive, view, appr, admin in sources:
        try:
            with winreg.OpenKey(hive, RUN, 0, winreg.KEY_READ | view) as k:
                i = 0
                while True:
                    try:
                        name, val, _t = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    sub = f"{APPROVED}\\{appr}"
                    items.append(_item(name, str(val), label, _approved_state(hive, sub, name), admin, hive, view, sub))
        except OSError:
            continue
    folders = [
        ("Startup folder (user)", os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
         winreg.HKEY_CURRENT_USER, False),
        ("Startup folder (all users)", os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
         winreg.HKEY_LOCAL_MACHINE, True),
    ]
    for label, folder, hive, admin in folders:
        if not os.path.isdir(folder):
            continue
        for fn in os.listdir(folder):
            if fn.lower() == "desktop.ini":
                continue
            sub = f"{APPROVED}\\StartupFolder"
            it = _item(fn, os.path.join(folder, fn), label, _approved_state(hive, sub, fn), admin, hive, 0, sub)
            it.kind = "folder"
            items.append(it)
    if include_tasks:
        items += list_tasks()
    if include_services:
        items += list_services()
    return items


def _item(name, cmd, source, enabled, admin, hive, view, sub) -> StartupItem:
    exe = os.path.basename(command_exe(cmd) or cmd)
    rec = bool(_NONESSENTIAL.search(name + " " + exe)) and not _KEEP.search(name + " " + exe)
    return StartupItem(name, cmd, source, enabled, rec, admin and not is_admin(), "run", hive, view, sub)


# ----------------------------------------------------------- scheduled tasks

def _ps_json(script: str, timeout: int = 90):
    r = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True,
                       timeout=timeout, creationflags=0x08000000)
    try:
        data = json.loads(r.stdout) if r.stdout.strip() else []
    except ValueError:
        return []
    return data if isinstance(data, list) else [data]


_TASK_PS = (
    "Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft*' -and $_.State -ne 'Disabled' } | "
    "ForEach-Object { $a=$_.Actions | Select-Object -First 1; $t=($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ','; "
    "[pscustomobject]@{Name=$_.TaskName; Path=$_.TaskPath; Exec=$a.Execute; Args=$a.Arguments; Triggers=$t} } | ConvertTo-Json"
)


def parse_tasks(rows: list[dict]) -> list[StartupItem]:
    out = []
    for r in rows:
        trig = r.get("Triggers") or ""
        if not re.search(r"(Logon|Boot)", trig):       # only tasks that run at sign-in/boot are "startup"
            continue
        cmd = f"{r.get('Exec') or ''} {r.get('Args') or ''}".strip()
        name = r["Name"]
        rec = bool(_NONESSENTIAL.search(name + " " + cmd)) and not _KEEP.search(name + " " + cmd)
        it = StartupItem(name, cmd, "Scheduled task", True, rec, not is_admin(), "task")
        it._task_path = r.get("Path") or "\\"
        out.append(it)
    return out


def list_tasks() -> list[StartupItem]:
    try:
        return parse_tasks(_ps_json(_TASK_PS))
    except (subprocess.SubprocessError, OSError):
        return []


# ------------------------------------------------------------------ services

_SVC_PS = ("Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName } | "
           "Select-Object Name,DisplayName,PathName,State | ConvertTo-Json")
_SYSTEM_PATH = re.compile(r"(\\windows\\|\\microsoft\\|windows defender|\\system32\\)", re.I)


def parse_services(rows: list[dict]) -> list[StartupItem]:
    out = []
    for r in rows:
        path = r.get("PathName") or ""
        if _SYSTEM_PATH.search(path):
            continue                                    # leave Windows' own services alone
        label = f"{r.get('DisplayName') or r['Name']}"
        rec = bool(_NONESSENTIAL.search(label + " " + path)) and not _KEEP.search(label + " " + path)
        it = StartupItem(label, path, "Service", True, rec, not is_admin(), "service")
        it._service = r["Name"]
        out.append(it)
    return out


def list_services() -> list[StartupItem]:
    try:
        return parse_services(_ps_json(_SVC_PS))
    except (subprocess.SubprocessError, OSError):
        return []


# ------------------------------------------------------------------- toggling

def set_enabled(item: StartupItem, enabled: bool) -> bool:
    if item.needs_admin:
        return False
    if item.kind == "task":
        verb = "Enable" if enabled else "Disable"
        ps = f"{verb}-ScheduledTask -TaskName '{item.name}' -TaskPath '{item._task_path}' -ErrorAction Stop | Out-Null"
        ok = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True,
                            creationflags=0x08000000).returncode == 0
    elif item.kind == "service":
        mode = "auto" if enabled else "demand"
        ok = subprocess.run(["sc.exe", "config", item._service, "start=", mode], capture_output=True,
                            creationflags=0x08000000).returncode == 0
    else:
        value = struct.pack("<I", 2 if enabled else 3) + (b"\x00" * 8 if enabled else struct.pack("<Q", _filetime()))
        try:
            with winreg.CreateKeyEx(item._hive, item._approved_sub, 0, winreg.KEY_WRITE | item._view) as k:
                winreg.SetValueEx(k, item.name, 0, winreg.REG_BINARY, value)
            ok = True
        except OSError:
            ok = False
    if ok:
        log_action("startup-enable" if enabled else "startup-disable", f"{item.source}: {item.name}")
        item.enabled = enabled
    return ok


def _filetime() -> int:
    return int((time.time() + 11644473600) * 10_000_000)
