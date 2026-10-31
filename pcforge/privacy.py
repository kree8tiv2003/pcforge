"""Privacy sweep: browser traces and Windows usage traces.

Targets are data-driven (BROWSERS below) so adding another browser is one line.
Passwords and autofill are separate, never pre-ticked categories.
"""
from __future__ import annotations

import ctypes
import glob
import os
import subprocess
import winreg

import psutil

from .safety import CleanResult, Finding, delete_path, filter_ignored, tree_size, log_action

LOCAL = os.environ.get("LOCALAPPDATA", "")
ROAM = os.environ.get("APPDATA", "")

# name -> (user-data dir, process name)
CHROMIUM = {
    "Google Chrome": (os.path.join(LOCAL, "Google", "Chrome", "User Data"), "chrome.exe"),
    "Microsoft Edge": (os.path.join(LOCAL, "Microsoft", "Edge", "User Data"), "msedge.exe"),
    "Brave": (os.path.join(LOCAL, "BraveSoftware", "Brave-Browser", "User Data"), "brave.exe"),
    "Vivaldi": (os.path.join(LOCAL, "Vivaldi", "User Data"), "vivaldi.exe"),
    "Opera": (os.path.join(ROAM, "Opera Software", "Opera Stable"), "opera.exe"),
    "Chromium": (os.path.join(LOCAL, "Chromium", "User Data"), "chromium.exe"),
    "Avast Secure Browser": (os.path.join(LOCAL, "AVAST Software", "Browser", "User Data"), "AvastBrowser.exe"),
    "AVG Secure Browser": (os.path.join(LOCAL, "AVG", "Browser", "User Data"), "AVGBrowser.exe"),
    "Opera GX": (os.path.join(ROAM, "Opera Software", "Opera GX Stable"), "opera.exe"),
    "Yandex Browser": (os.path.join(LOCAL, "Yandex", "YandexBrowser", "User Data"), "browser.exe"),
    "Epic Privacy Browser": (os.path.join(LOCAL, "Epic Privacy Browser", "User Data"), "epic.exe"),
}
# category -> relative paths inside a Chromium profile
CHROMIUM_CATS = {
    "cache": ["Cache", "Code Cache", "GPUCache", "DawnCache", os.path.join("Service Worker", "CacheStorage"),
              os.path.join("Service Worker", "ScriptCache"), "Media Cache"],
    "history": ["History", "History-journal", "Visited Links", "Top Sites", "Favicons", "Shortcuts"],
    "cookies": [os.path.join("Network", "Cookies"), os.path.join("Network", "Cookies-journal"), "Cookies"],
    "passwords": ["Login Data", "Login Data-journal", "Login Data For Account"],
    "autofill": ["Web Data", "Web Data-journal"],
}
FIREFOX_ROAM = os.path.join(ROAM, "Mozilla", "Firefox", "Profiles")
FIREFOX_LOCAL = os.path.join(LOCAL, "Mozilla", "Firefox", "Profiles")
# Firefox history lives in places.sqlite together with bookmarks, so we do not touch it.
FIREFOX_CATS = {
    "cache": [(FIREFOX_LOCAL, "cache2"), (FIREFOX_LOCAL, "startupCache")],
    "cookies": [(FIREFOX_ROAM, "cookies.sqlite"), (FIREFOX_ROAM, "cookies.sqlite-wal")],
    "passwords": [(FIREFOX_ROAM, "logins.json"), (FIREFOX_ROAM, "key4.db")],
}
DEFAULT_ON = {"cache"}   # history/cookies/passwords/autofill must be ticked deliberately
RISK = {"cache": "low", "history": "medium", "cookies": "medium", "passwords": "high", "autofill": "high"}


def _running(proc: str) -> bool:
    return any((p.info["name"] or "").lower() == proc for p in psutil.process_iter(["name"]))


def _chromium_profiles(root: str) -> list[str]:
    if not os.path.isdir(root):
        return []
    profs = [p for p in glob.glob(os.path.join(root, "Default")) + glob.glob(os.path.join(root, "Profile *"))
             if os.path.isdir(p)]
    return profs or ([root] if os.path.exists(os.path.join(root, "History")) else [])  # Opera layout


def browser_roots() -> list[str]:
    roots = [v[0] for v in CHROMIUM.values()] + [FIREFOX_ROAM, FIREFOX_LOCAL]
    return [r for r in roots if r]


def scan_browsers() -> list[Finding]:
    out: list[Finding] = []
    for name, (root, proc) in CHROMIUM.items():
        busy = _running(proc)
        for prof in _chromium_profiles(root):
            for cat, rels in CHROMIUM_CATS.items():
                for rel in rels:
                    full = os.path.join(prof, rel)
                    if os.path.exists(full):
                        out.append(_find(name, cat, full, busy, root))
    ff_busy = _running("firefox.exe")
    for cat, pairs in FIREFOX_CATS.items():
        for base, rel in pairs:
            for prof in glob.glob(os.path.join(base, "*")):
                full = os.path.join(prof, rel)
                if os.path.exists(full):
                    out.append(_find("Firefox", cat, full, ff_busy, base))
    return filter_ignored([f for f in out if f.size > 0])


def _find(browser: str, cat: str, path: str, busy: bool, root: str) -> Finding:
    return Finding(f"browser-{cat}", f"{browser} {cat}", path, tree_size(path), risk=RISK[cat],
                   selected=cat in DEFAULT_ON, meta=dict(roots=[root], browser_running=busy))


# ------------------------------------------------------------ Windows traces

RUNMRU = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
TYPEDPATHS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"


def scan_windows_traces() -> list[Finding]:
    recent = os.path.join(ROAM, "Microsoft", "Windows", "Recent")
    out: list[Finding] = []
    for sub, label in ((None, "Recent files list"), ("AutomaticDestinations", "Jump lists"),
                       ("CustomDestinations", "Jump lists")):
        d = recent if sub is None else os.path.join(recent, sub)
        if not os.path.isdir(d):
            continue
        size = sum(e.stat().st_size for e in os.scandir(d) if e.is_file(follow_symlinks=False))
        if size:
            out.append(Finding("win-recent", label, d, size, meta=dict(children_of=d, roots=[recent])))
    applets = r"Software\Microsoft\Windows\CurrentVersion\Applets"
    for sub, label in ((RUNMRU, "Run dialog history"), (TYPEDPATHS, "Explorer typed paths"),
                       (applets + r"\Paint\Recent File List", "Paint recent files"),
                       (applets + r"\Wordpad\Recent File List", "WordPad recent files")):
        if _reg_has_values(sub):
            out.append(Finding("win-reg", label, f"HKCU\\{sub}", 0, meta=dict(regkey=sub)))
    # "most recently used programs" list; clearing it resets Start-menu frequent apps, so it is opt-in
    ua = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua, 0, winreg.KEY_READ) as k:
            guids = [winreg.EnumKey(k, i) for i in range(winreg.QueryInfoKey(k)[0])]
        for g in guids:
            if _reg_has_values(f"{ua}\\{g}\\Count"):
                out.append(Finding("win-reg", "Recently used programs (UserAssist)", f"HKCU\\{ua}\\{g}\\Count", 0,
                                   selected=False, meta=dict(regkey=f"{ua}\\{g}\\Count")))
    except OSError:
        pass
    out.append(Finding("win-dns", "DNS resolver cache", "dns", 0, meta=dict(special="dns")))
    out.append(Finding("win-clip", "Clipboard contents", "clipboard", 0, selected=False, meta=dict(special="clipboard")))
    return out


def _reg_has_values(sub: str) -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0, winreg.KEY_READ) as k:
            return winreg.QueryInfoKey(k)[1] > 0
    except OSError:
        return False


def _clear_reg_values(sub: str) -> None:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
        names = []
        i = 0
        while True:
            try:
                names.append(winreg.EnumValue(k, i)[0])
                i += 1
            except OSError:
                break
        for n in names:
            winreg.DeleteValue(k, n)


def _clear_clipboard() -> None:
    u = ctypes.windll.user32
    if u.OpenClipboard(None):
        u.EmptyClipboard()
        u.CloseClipboard()


def sweep(findings: list[Finding], dry_run: bool = True) -> CleanResult:
    res = CleanResult()
    for f in findings:
        m = f.meta
        sp = m.get("special")
        if sp == "dns":
            if not dry_run:
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=0x08000000)
            res.add(f.path, 0, None)
        elif sp == "clipboard":
            if not dry_run:
                _clear_clipboard()
            res.add(f.path, 0, None)
        elif "regkey" in m:
            if not dry_run:
                try:
                    _clear_reg_values(m["regkey"])
                except OSError as e:
                    res.skipped.append((f.path, str(e)))
                    continue
            res.add(f.path, 0, None)
        elif "children_of" in m:                       # delete the files inside a folder, keep the folder
            for e in os.scandir(m["children_of"]):
                if e.is_file(follow_symlinks=False):
                    freed, err = delete_path(e.path, [m["children_of"]], dry_run)
                    res.add(e.path, freed, err)
        else:
            if m.get("browser_running"):
                res.skipped.append((f.path, "browser is open; close it first"))
                continue
            freed, err = delete_path(f.path, m.get("roots", []), dry_run)
            res.add(f.path, freed, err)
    if not dry_run:
        log_action("privacy-sweep", f"{res.removed} items")
    return res
