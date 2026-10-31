"""Junk-file cleaner, invalid-shortcut finder and leftover-folder finder.

Every finding carries its own root (and file pattern, when the category is a
pattern like thumbcache_*.db). clean() refuses to delete anything that is not
strictly inside that root and does not match that pattern.
"""
from __future__ import annotations

import ctypes
import fnmatch
import glob
import os
import re
import struct
import time
from ctypes import wintypes

from .registry_cleaner import definitely_missing
from .safety import CleanResult, Finding, delete_path, filter_ignored, is_admin, is_link, tree_size

ENV = os.environ.get


def _p(*parts: str) -> str:
    return os.path.join(*parts)


def _junk_categories(min_age_scale: float = 1.0) -> list[dict]:
    """min_age_scale lets the UI implement 'keep files from the last N days' by scaling ages."""
    local, roam = ENV("LOCALAPPDATA", ""), ENV("APPDATA", "")
    prog = ENV("ProgramData", r"C:\ProgramData")
    win = ENV("SystemRoot", r"C:\Windows")
    day = 24

    cats = [
        dict(id="user_temp", label="User temp files", roots=[ENV("TEMP", "")], min_age_h=day),
        dict(id="win_temp", label="Windows temp files", roots=[_p(win, "Temp")], min_age_h=day, admin=True),
        dict(id="inet_cache", label="Windows internet cache", roots=[_p(local, "Microsoft", "Windows", "INetCache")], min_age_h=day),
        dict(id="d3d_cache", label="Graphics shader cache",
             roots=[_p(local, "D3DSCache"), _p(local, "NVIDIA", "DXCache"), _p(local, "NVIDIA", "GLCache"),
                    _p(local, "AMD", "DxCache"), _p(local, "AMD", "GLCache")], min_age_h=day),
        dict(id="thumbs", label="Thumbnail cache", roots=[_p(local, "Microsoft", "Windows", "Explorer")],
             pattern="thumbcache_*.db", min_age_h=0),
        dict(id="crash", label="Crash dumps", roots=[_p(local, "CrashDumps"), _p(win, "Minidump")], min_age_h=0),
        dict(id="memdump", label="Memory dump files", roots=[win], pattern="MEMORY.DMP", min_age_h=day, admin=True),
        dict(id="livedump", label="Kernel live reports", roots=[_p(win, "LiveKernelReports")], pattern="*.dmp",
             min_age_h=day, admin=True),
        dict(id="wer", label="Error-report archives",
             roots=[_p(local, "Microsoft", "Windows", "WER"), _p(prog, "Microsoft", "Windows", "WER", "ReportArchive"),
                    _p(prog, "Microsoft", "Windows", "WER", "ReportQueue")], min_age_h=0),
        dict(id="wu_download", label="Windows Update download cache",
             roots=[_p(win, "SoftwareDistribution", "Download")], min_age_h=day, admin=True),
        dict(id="delivery_opt", label="Delivery Optimization cache",
             roots=[_p(win, "ServiceProfiles", "NetworkService", "AppData", "Local", "Microsoft", "Windows",
                       "DeliveryOptimization", "Cache")], min_age_h=day, admin=True),
        dict(id="cbs_logs", label="Windows log files", roots=[_p(win, "Logs", "CBS"), _p(win, "Logs", "DISM")],
             pattern="*.log", min_age_h=day * 7, admin=True),
        dict(id="win_root_logs", label="Windows log files", roots=[win], pattern="*.log", min_age_h=day * 7, admin=True),
        dict(id="prefetch", label="Old Prefetch data", roots=[_p(win, "Prefetch")], pattern="*.pf",
             min_age_h=day * 30, admin=True),
        dict(id="chkdsk", label="Disk-check file fragments", roots=[glob.escape(ENV("SystemDrive", "C:") + "\\") + "found.*"],
             pattern="*.chk", min_age_h=day * 7, admin=True),
        dict(id="iis_logs", label="IIS log files", roots=[_p(ENV("SystemDrive", "C:") + "\\", "inetpub", "logs", "LogFiles")],
             min_age_h=day * 7, admin=True),
        dict(id="office_cache", label="Microsoft Office cache",
             roots=[_p(local, "Microsoft", "Office", "16.0", "OfficeFileCache")], min_age_h=day),
        dict(id="defender_hist", label="Windows Defender scan history",
             roots=[_p(prog, "Microsoft", "Windows Defender", "Scans", "History", "Results", "Quick")],
             min_age_h=day * 7, admin=True),
        dict(id="store_temp", label="Microsoft Store app temp files", roots=[_p(local, "Packages", "*", "TempState")], min_age_h=day),
        dict(id="store_inet", label="Microsoft Store app cache", roots=[_p(local, "Packages", "*", "AC", "INetCache")], min_age_h=day),
    ]
    # Chromium-based desktop apps keep disposable caches under Roaming.
    for app in ("Discord", "Slack", "Code", _p("Microsoft", "Teams"), "Spotify", "Signal", "WhatsApp"):
        cats.append(dict(id="electron_cache", label="Desktop app caches",
                         roots=[_p(roam, app, sub) for sub in ("Cache", "Code Cache", "GPUCache", "DawnCache",
                                                                _p("Service Worker", "CacheStorage"))],
                         min_age_h=day))
    for c in cats:
        c["min_age_h"] *= min_age_scale
    return cats


def _expand(root: str) -> list[str]:
    return glob.glob(root) if "*" in root else [root]


def _children(root: str, pattern: str | None) -> list[str]:
    if pattern:
        return glob.glob(os.path.join(root, pattern))
    try:
        return [e.path for e in os.scandir(root)]
    except OSError:
        return []


def scan_junk(keep_days_scale: float = 1.0) -> list[Finding]:
    now = time.time()
    out: list[Finding] = []
    for cat in _junk_categories(keep_days_scale):
        admin_needed = cat.get("admin", False)
        for raw_root in cat["roots"]:
            if not raw_root:
                continue
            for root in _expand(raw_root):
                if not os.path.isdir(root):
                    continue
                for child in _children(root, cat.get("pattern")):
                    try:
                        age_h = (now - os.lstat(child).st_mtime) / 3600
                    except OSError:
                        continue
                    if age_h < cat["min_age_h"]:
                        continue
                    size = tree_size(child)
                    if size == 0:
                        continue                      # empty files/folders aren't worth showing
                    out.append(Finding(cat["id"], cat["label"], child, size,
                                       needs_admin=admin_needed and not is_admin(),
                                       meta=dict(root=root, pattern=cat.get("pattern"))))
    rb = recycle_bin_size()
    if rb:
        out.append(Finding("recycle", "Recycle Bin", "$RECYCLE.BIN", rb, meta={"special": "recycle"}))
    return filter_ignored(out)


def summarize(findings: list[Finding]) -> dict[str, tuple[int, int]]:
    """label -> (count, bytes)"""
    agg: dict[str, list[int]] = {}
    for f in findings:
        a = agg.setdefault(f.label, [0, 0])
        a[0] += 1
        a[1] += f.size
    return {k: (v[0], v[1]) for k, v in agg.items()}


def _allowed(f: Finding) -> bool:
    pat = f.meta.get("pattern")
    return not pat or fnmatch.fnmatch(os.path.basename(f.path).lower(), pat.lower())


def clean(findings: list[Finding], dry_run: bool = True) -> CleanResult:
    res = CleanResult()
    for f in findings:
        if f.meta.get("special") == "recycle":
            if not dry_run:
                empty_recycle_bin()
            res.add(f.path, f.size, None)
            continue
        if f.needs_admin:
            res.skipped.append((f.path, "needs administrator"))
            continue
        root = f.meta.get("root")
        if not root or not _allowed(f):
            res.skipped.append((f.path, "no safe root recorded"))
            continue
        freed, err = delete_path(f.path, [root], dry_run)
        res.add(f.path, freed, err)
    return res


# ------------------------------------------------------------- recycle bin

class _SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("i64Size", ctypes.c_longlong), ("i64NumItems", ctypes.c_longlong)]


def recycle_bin_size() -> int:
    info = _SHQUERYRBINFO(ctypes.sizeof(_SHQUERYRBINFO), 0, 0)
    try:
        if ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info)) == 0:
            return int(info.i64Size)
    except Exception:
        pass
    return 0


def empty_recycle_bin() -> bool:
    flags = 0x1 | 0x2 | 0x4  # no confirmation, no progress UI, no sound
    try:
        return ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, flags) in (0, 1)
    except Exception:
        return False


# ------------------------------------------------------------ .lnk shortcuts

def parse_lnk(path: str) -> dict:
    """Read the parts of a .lnk we need: {'target': local path or None, 'icon': icon file or None}.
    Anything that can't be read with confidence stays None (shell-item-only links, network targets)."""
    out = {"target": None, "icon": None}
    try:
        with open(path, "rb") as fh:
            data = fh.read(65536)
    except OSError:
        return out
    if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C:
        return out
    flags = struct.unpack_from("<I", data, 0x14)[0]
    off = 0x4C
    try:
        if flags & 0x1:  # HasLinkTargetIDList
            off += 2 + struct.unpack_from("<H", data, off)[0]
        if flags & 0x2:  # HasLinkInfo
            info_size, _hdr, info_flags, _vol, local_off = struct.unpack_from("<IIIII", data, off)
            if info_flags & 0x1 and off + info_size <= len(data):
                suffix_off = struct.unpack_from("<I", data, off + 24)[0]

                def cstr(o: int) -> str:
                    end = data.find(b"\x00", o)
                    return data[o:end].decode("mbcs", "replace") if end > o else ""

                out["target"] = (cstr(off + local_off) + (cstr(off + suffix_off) if suffix_off else "")) or None
            off += info_size
        # StringData: name, relative path, working dir, arguments, icon location (in that order)
        unicode_strings = bool(flags & 0x80)
        for bit in (0x4, 0x8, 0x10, 0x20, 0x40):
            if not flags & bit:
                continue
            n = struct.unpack_from("<H", data, off)[0]
            off += 2
            width = 2 * n if unicode_strings else n
            text = data[off:off + width].decode("utf-16le" if unicode_strings else "mbcs", "replace")
            off += width
            if bit == 0x40:
                out["icon"] = text
    except struct.error:
        pass
    return out


def parse_lnk_target(path: str) -> str | None:
    return parse_lnk(path)["target"]


def _icon_file(icon: str | None) -> str | None:
    """'%SystemRoot%\\x.dll,3' -> expanded file path without the resource index."""
    if not icon:
        return None
    return os.path.expandvars(icon.rsplit(",", 1)[0] if re.search(r",-?\d+$", icon) else icon).strip('"')


def scan_shortcuts() -> list[Finding]:
    dirs = [
        os.path.join(ENV("USERPROFILE", ""), "Desktop"),
        os.path.join(ENV("PUBLIC", r"C:\Users\Public"), "Desktop"),
        os.path.join(ENV("APPDATA", ""), "Microsoft", "Windows", "Start Menu"),
        os.path.join(ENV("ProgramData", ""), "Microsoft", "Windows", "Start Menu"),
    ]
    dirs.append(os.path.join(ENV("APPDATA", ""), "Microsoft", "Internet Explorer", "Quick Launch"))
    local = ENV("LOCALAPPDATA", "")
    # Installed web apps keep their own shortcut copies here; the original checks them too.
    for browser in (("Google", "Chrome"), ("Microsoft", "Edge"), ("BraveSoftware", "Brave-Browser")):
        dirs += glob.glob(os.path.join(local, *browser, "User Data", "*", "Web Applications"))
    out: list[Finding] = []
    for d in dirs:
        for dirpath, _dn, files in os.walk(d):
            for name in files:
                if not name.lower().endswith(".lnk"):
                    continue
                full = os.path.join(dirpath, name)
                info = parse_lnk(full)
                admin = not is_admin() and (d.startswith(ENV("ProgramData", "\0")) or d.startswith(ENV("PUBLIC", "\0")))
                target = info["target"]
                if target and definitely_missing(target):
                    out.append(Finding("shortcut", "Broken shortcut (target missing)", full, os.path.getsize(full),
                                       needs_admin=admin, meta={"target": target, "roots": dirs}))
                    continue
                icon = _icon_file(info["icon"])
                if icon and definitely_missing(icon):
                    # The original counts these too. Deleting a working shortcut over a missing icon is a
                    # judgement call, so they are listed but never pre-selected.
                    out.append(Finding("shortcut-icon", "Shortcut with missing icon", full, os.path.getsize(full),
                                       selected=False, needs_admin=admin, meta={"icon": icon, "roots": dirs}))
    return filter_ignored(out)


def clean_shortcuts(findings: list[Finding], dry_run: bool = True) -> CleanResult:
    res = CleanResult()
    for f in findings:
        if f.needs_admin:
            res.skipped.append((f.path, "needs administrator"))
            continue
        freed, err = delete_path(f.path, f.meta.get("roots", []), dry_run)
        res.add(f.path, freed, err)
    return res


# ------------------------------------------------------ leftover program dirs

_KEEP = {"common files", "windows nt", "windowsapps", "microsoft", "windows defender", "windows mail",
         "windows media player", "windows photo viewer", "windows portable devices", "windows security",
         "reference assemblies", "internet explorer", "dotnet", "uninstall information", "msbuild",
         "modifiablewindowsapps", "windows sidebar", "microsoft.net", "package cache"}
_BINARY_EXT = (".exe", ".dll", ".sys", ".msi", ".bat", ".cmd", ".ps1", ".jar", ".py", ".node")


def scan_leftover_folders() -> list[Finding]:
    """Program Files folders that contain no program files at all (shells left by
    uninstallers). Reported as medium risk and NOT pre-selected."""
    out: list[Finding] = []
    for base in {ENV("ProgramFiles", ""), ENV("ProgramFiles(x86)", "")}:
        if not base or not os.path.isdir(base):
            continue
        for e in os.scandir(base):
            if not e.is_dir(follow_symlinks=False) or e.name.lower() in _KEEP or is_link(e.path):
                continue
            has_binary = False
            for _d, _dn, files in os.walk(e.path):
                if any(f.lower().endswith(_BINARY_EXT) for f in files):
                    has_binary = True
                    break
            if not has_binary:
                out.append(Finding("leftover", "Empty program folder", e.path, tree_size(e.path), risk="medium",
                                   selected=False, needs_admin=not is_admin(), meta={"roots": [base]}))
    return filter_ignored(out)


def clean_leftovers(findings: list[Finding], dry_run: bool = True) -> CleanResult:
    res = CleanResult()
    for f in findings:
        if f.needs_admin:
            res.skipped.append((f.path, "needs administrator"))
            continue
        freed, err = delete_path(f.path, f.meta.get("roots", []), dry_run)
        res.add(f.path, freed, err)
    return res
