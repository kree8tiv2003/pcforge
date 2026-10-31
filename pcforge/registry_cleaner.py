"""Conservative registry cleaner.

Only flags entries whose target is an absolute path on a present fixed drive that
no longer exists. Anything ambiguous is left alone. Every fix first exports the
key to a .reg backup, which `restore_backup` can re-import.
"""
from __future__ import annotations

import ctypes
import os
import re
import subprocess
import time
import winreg
from pathlib import Path

from .safety import CleanResult, Finding, create_restore_point, data_dir, filter_ignored, is_admin, log_action

HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
VIEWS = {"64": winreg.KEY_WOW64_64KEY, "32": winreg.KEY_WOW64_32KEY}

_EXE_RE = re.compile(r'^(.+?\.(?:exe|bat|cmd|com|scr|dll|msi))(\s|,|/|$)', re.I)


def _is_windows_owned(path: str | None) -> bool:
    """Never judge files inside the Windows folder; they can be hidden by redirection or protection."""
    root = os.environ.get("SystemRoot", r"C:\Windows").lower().rstrip("\\") + "\\"
    return bool(path) and os.path.expandvars(path).lower().startswith(root)


def command_exe(cmd: str) -> str | None:
    """Pull the program path out of a command line, or None."""
    cmd = os.path.expandvars((cmd or "").strip())
    if not cmd:
        return None
    if cmd[0] == '"':
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 1 else None
    m = _EXE_RE.match(cmd)
    return m.group(1) if m else None


def definitely_missing(path: str | None) -> bool:
    """True only for an absolute local path on a present fixed drive that doesn't exist."""
    if not path or _is_windows_owned(path):
        return False
    path = os.path.expandvars(path)
    if len(path) < 3 or path[1:3] != ":\\":
        return False
    drive = path[:3]
    if not os.path.exists(drive) or ctypes.windll.kernel32.GetDriveTypeW(drive) != 3:
        return False
    return not os.path.exists(path)


def _open(hive: str, sub: str, view: str, write: bool = False):
    access = winreg.KEY_READ | VIEWS[view]
    if write:
        access |= winreg.KEY_WRITE
    return winreg.OpenKey(HIVES[hive], sub, 0, access)


def _subkeys(key) -> list[str]:
    out, i = [], 0
    while True:
        try:
            out.append(winreg.EnumKey(key, i))
            i += 1
        except OSError:
            return out


def _values(key) -> list[tuple[str, object, int]]:
    out, i = [], 0
    while True:
        try:
            out.append(winreg.EnumValue(key, i))
            i += 1
        except OSError:
            return out


def _get(key, name: str):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


APP_PATHS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
SHARED = r"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs"


def scan_registry(include_risky: bool = True) -> list[Finding]:
    """Categories mirror the original's list: App Paths, Software, Startup Items, Shared Files, Fonts,
    Help Files, MUI Cache, Sounds, Windows Services, ActiveX/COM. Risky ones are never pre-selected."""
    out: list[Finding] = []
    for view in ("64", "32"):
        out += _scan_app_paths(view)
        out += _scan_uninstall("HKLM", view)
    out += _scan_uninstall("HKCU", "64")
    for hive in ("HKLM", "HKCU"):
        out += _scan_run(hive, "64")
    out += _scan_shared()
    out += _scan_fonts()
    out += _scan_help()
    out += _scan_mui()
    out += _scan_sounds()
    if include_risky:
        out += _scan_services()
        out += _scan_com()
    return filter_ignored(out)


def _mk(cat, label, hive, sub, view, value=None, detail="", risk="low"):
    return Finding(cat, label, f"{hive}\\{sub}" + (f"  [{value}]" if value else ""), 0, risk=risk,
                   selected=(risk == "low"), needs_admin=(hive == "HKLM" and not is_admin()),
                   meta=dict(hive=hive, sub=sub, view=view, value=value, detail=detail))


FONTS = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
HELP = r"SOFTWARE\Microsoft\Windows\Help"
MUI = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
SOUNDS = r"AppEvents\Schemes\Apps"
SERVICES = r"SYSTEM\CurrentControlSet\Services"
CLSID = r"SOFTWARE\Classes\CLSID"


def _scan_fonts():
    out, fontdir = [], os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Fonts")
    try:
        with _open("HKLM", FONTS, "64") as k:
            for name, val, _t in _values(k):
                if not isinstance(val, str) or "." not in val[-6:]:
                    continue
                path = val if ":" in val else os.path.join(fontdir, val)
                if definitely_missing(path):
                    out.append(_mk("regfont", "Missing font file", "HKLM", FONTS, "64", value=name, detail=path))
    except OSError:
        pass
    return out


def _scan_help():
    out = []
    try:
        with _open("HKLM", HELP, "64") as k:
            for name, val, _t in _values(k):
                if isinstance(val, str) and definitely_missing(val):
                    out.append(_mk("reghelp", "Missing help file location", "HKLM", HELP, "64", value=name, detail=val))
    except OSError:
        pass
    return out


_MUI_RE = re.compile(r"^(.+?\.(?:exe|dll|cpl|msc))\.", re.I)


def _scan_mui():
    out = []
    try:
        with _open("HKCU", MUI, "64") as k:
            for name, _val, _t in _values(k):
                m = _MUI_RE.match(name)
                if m and definitely_missing(m.group(1)):
                    out.append(_mk("regmui", "Stale program name cache (MUI)", "HKCU", MUI, "64", value=name, detail=m.group(1)))
    except OSError:
        pass
    return out


def _scan_sounds():
    out = []
    try:
        with _open("HKCU", SOUNDS, "64") as apps:
            for app in _subkeys(apps):
                with _open("HKCU", f"{SOUNDS}\\{app}", "64") as ak:
                    for event in _subkeys(ak):
                        sub = f"{SOUNDS}\\{app}\\{event}\\.Current"
                        try:
                            with _open("HKCU", sub, "64") as ck:
                                wav = _get(ck, "")
                        except OSError:
                            continue
                        if isinstance(wav, str) and wav and definitely_missing(os.path.expandvars(wav)):
                            out.append(_mk("regsound", "Missing sound file", "HKCU", sub, "64", value="", detail=wav))
    except OSError:
        pass
    return out


def _scan_services():
    """Services/drivers whose program file is gone. Medium risk: never pre-selected, never in AI Mode."""
    out = []
    try:
        with _open("HKLM", SERVICES, "64") as k:
            for name in _subkeys(k):
                try:
                    with _open("HKLM", f"{SERVICES}\\{name}", "64") as sk:
                        img = _get(sk, "ImagePath")
                except OSError:
                    continue
                if not isinstance(img, str):
                    continue
                img = img.replace("\\??\\", "")
                exe = command_exe(img) or (img if img.lower().endswith(".sys") else None)
                if definitely_missing(exe):
                    out.append(_mk("regsvc", "Service with missing program", "HKLM", f"{SERVICES}\\{name}", "64",
                                   detail=exe, risk="medium"))
    except OSError:
        pass
    return out


def _scan_com():
    """COM/ActiveX classes whose DLL is gone (the original's 'ActiveX and Component' category)."""
    out = []
    try:
        with _open("HKLM", CLSID, "64") as k:
            for guid in _subkeys(k):
                for srv in ("InprocServer32", "LocalServer32"):
                    try:
                        with _open("HKLM", f"{CLSID}\\{guid}\\{srv}", "64") as sk:
                            path = _get(sk, "")
                    except OSError:
                        continue
                    if isinstance(path, str):
                        exe = command_exe(path) or path.strip('"')
                        if definitely_missing(exe):
                            out.append(_mk("regcom", "ActiveX/COM class with missing file", "HKLM",
                                           f"{CLSID}\\{guid}", "64", detail=exe, risk="medium"))
                            break
    except OSError:
        pass
    return out


def _scan_app_paths(view):
    out = []
    try:
        with _open("HKLM", APP_PATHS, view) as k:
            for name in _subkeys(k):
                with _open("HKLM", f"{APP_PATHS}\\{name}", view) as sk:
                    target = _get(sk, "")
                    if definitely_missing(command_exe(target) or target):
                        out.append(_mk("regapp", "Missing application path", "HKLM", f"{APP_PATHS}\\{name}", view, detail=str(target)))
    except OSError:
        pass
    return out


def _scan_uninstall(hive, view):
    out = []
    try:
        with _open(hive, UNINSTALL, view) as k:
            for name in _subkeys(k):
                try:
                    with _open(hive, f"{UNINSTALL}\\{name}", view) as sk:
                        if not _get(sk, "DisplayName") or _get(sk, "SystemComponent") == 1:
                            continue
                        loc = _get(sk, "InstallLocation")
                        if loc and os.path.exists(os.path.expandvars(loc)):
                            continue
                        exe = command_exe(_get(sk, "UninstallString") or "")
                        if definitely_missing(exe):
                            out.append(_mk("reguninst", "Orphaned uninstall entry", hive, f"{UNINSTALL}\\{name}", view,
                                           detail=f"{_get(sk, 'DisplayName')} -> {exe}"))
                except OSError:
                    continue
    except OSError:
        pass
    return out


def _scan_run(hive, view):
    out = []
    try:
        with _open(hive, RUN, view) as k:
            for name, val, _t in _values(k):
                if isinstance(val, str) and definitely_missing(command_exe(val)):
                    out.append(_mk("regrun", "Startup entry with missing program", hive, RUN, view, value=name, detail=val))
    except OSError:
        pass
    return out


def _scan_shared():
    out = []
    try:
        with _open("HKLM", SHARED, "64") as k:
            for name, _val, _t in _values(k):
                if definitely_missing(name):
                    out.append(_mk("regdll", "Missing shared DLL reference", "HKLM", SHARED, "64", value=name))
    except OSError:
        pass
    return out


# ------------------------------------------------------------------ fixing

def backup_dir() -> Path:
    d = data_dir() / "registry-backups" / time.strftime("%Y%m%d-%H%M%S")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _export(hive: str, sub: str, view: str, dest: Path) -> bool:
    arch = "/reg:32" if view == "32" else "/reg:64"
    r = subprocess.run(["reg", "export", f"{hive}\\{sub}", str(dest), "/y", arch],
                       capture_output=True, text=True, creationflags=0x08000000)
    return r.returncode == 0 and dest.exists()


def _delete_tree(hive: str, sub: str, view: str) -> None:
    with _open(hive, sub, view, write=True) as k:
        for child in _subkeys(k):
            _delete_tree(hive, f"{sub}\\{child}", view)
    winreg.DeleteKeyEx(HIVES[hive], sub, VIEWS[view], 0)


def fix_registry(findings: list[Finding], dry_run: bool = True) -> CleanResult:
    res = CleanResult()
    bdir = None
    for i, f in enumerate(findings):
        m = f.meta
        if f.needs_admin:
            res.skipped.append((f.path, "needs administrator"))
            continue
        if dry_run:
            res.add(f.path, 0, None)
            continue
        if bdir is None:
            bdir = backup_dir()
            if any(x.meta.get("hive") == "HKLM" for x in findings):
                ok, why = create_restore_point()      # best effort; the per-key .reg backups are the real safety net
                log_action("registry-restore-point", why, ok=ok)
        parent_key = m["sub"]
        if not _export(m["hive"], parent_key, m["view"], bdir / f"{i:04d}.reg"):
            res.skipped.append((f.path, "backup failed, left untouched"))
            continue
        try:
            if m["value"] is None:
                _delete_tree(m["hive"], m["sub"], m["view"])
            else:
                with _open(m["hive"], m["sub"], m["view"], write=True) as k:
                    winreg.DeleteValue(k, m["value"])
            log_action("registry-delete", f.path, backup=str(bdir))
            res.add(f.path, 0, None)
        except OSError as e:
            res.skipped.append((f.path, str(e)))
    return res


def list_backups() -> list[Path]:
    root = data_dir() / "registry-backups"
    return sorted(p for p in root.glob("*") if p.is_dir()) if root.exists() else []


def restore_backup(folder: Path) -> int:
    n = 0
    for reg in sorted(Path(folder).glob("*.reg")):
        if subprocess.run(["reg", "import", str(reg)], capture_output=True, creationflags=0x08000000).returncode == 0:
            n += 1
    log_action("registry-restore", str(folder), files=n)
    return n
