"""User-mode protection: threat heuristics, Defender integration, URL/e-mail
checks, hosts-file blocking and a folder guard.

Honest scope: this runs in user mode, so it can scan, warn and block at the DNS
level, but it cannot intercept file opens the way a kernel filter driver can.
Pair it with Microsoft Defender (see `defender_*`) for real-time engine coverage.
"""
from __future__ import annotations

import email
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time
from email import policy
from pathlib import Path
from urllib.parse import urlparse

from . import brand
from .safety import Finding, data_dir, is_admin, log_action

# --------------------------------------------------------------- file scanner

# Split on purpose: keeps this source file itself from tripping antivirus engines.
_EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()
SCAN_EXT = (".exe", ".dll", ".scr", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".jar", ".msi", ".lnk", ".com", ".hta", ".wsf")
SCRIPT_EXT = (".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta", ".wsf")
DOC_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".mp3", ".mp4")
MAX_HASH = 64 * 1024 * 1024


def blocklist_path() -> Path:
    return data_dir() / "blocklist_sha256.txt"


def load_hash_blocklist() -> set[str]:
    p = blocklist_path()
    if not p.exists():
        p.write_text("# one SHA-256 per line; lines starting with # are ignored\n", encoding="utf-8")
    return {ln.split()[0].lower() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")}


def sha256(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def default_scan_dirs() -> list[str]:
    home = os.environ.get("USERPROFILE", "")
    return [os.path.join(home, "Downloads"), os.path.join(home, "Desktop"), os.environ.get("TEMP", ""),
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")]


def check_file(path: str, blocklist: set[str]) -> Finding | None:
    name = os.path.basename(path).lower()
    reasons: list[str] = []
    risk = "low"
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    # double extension: report.pdf.exe
    stem, ext = os.path.splitext(name)
    if ext in SCAN_EXT and os.path.splitext(stem)[1] in DOC_EXT:
        reasons.append("disguised double extension")
        risk = "high"
    low = path.lower()
    temp = os.environ.get("TEMP", "\0").lower()
    if ext in SCRIPT_EXT and (low.startswith(temp) or "\\start menu\\programs\\startup\\" in low):
        reasons.append("script in startup/temp folder")
        risk = "medium" if risk == "low" else risk
    if size <= MAX_HASH and ext in SCAN_EXT + (".txt", ".com"):
        digest = sha256(path)
        if digest and digest in blocklist:
            reasons.append("hash on your blocklist")
            risk = "high"
        try:
            with open(path, "rb") as fh:
                if _EICAR in fh.read(1024):
                    reasons.append("antivirus test signature (EICAR)")
                    risk = "high"
        except OSError:
            pass
    if not reasons:
        return None
    return Finding("threat", "; ".join(reasons), path, size, risk=risk, selected=False)


def scan_threats(dirs: list[str] | None = None, max_files: int = 20000) -> list[Finding]:
    block = load_hash_blocklist()
    out, seen = [], 0
    for d in dirs or default_scan_dirs():
        for dirpath, _dn, files in os.walk(d):
            for fn in files:
                seen += 1
                if seen > max_files:
                    return out
                f = check_file(os.path.join(dirpath, fn), block)
                if f:
                    out.append(f)
    return out


def quarantine(path: str) -> str | None:
    """Move a file into the quarantine folder (reversible); never deletes."""
    qdir = data_dir() / "quarantine"
    qdir.mkdir(exist_ok=True)
    dest = qdir / f"{int(time.time())}_{os.path.basename(path)}.quarantined"
    try:
        shutil.move(path, dest)
    except OSError:
        return None
    (qdir / (dest.name + ".json")).write_text(json.dumps({"original": path}), encoding="utf-8")
    log_action("quarantine", path)
    return str(dest)


def unsigned_autorun_targets() -> list[Finding]:
    """Autorun programs without a valid Authenticode signature (asks PowerShell)."""
    from .registry_cleaner import command_exe
    from .startup import list_startup

    exes = {}
    for it in list_startup():
        exe = command_exe(it.command)
        if exe and os.path.exists(exe):
            exes[exe] = it.name
    if not exes:
        return []
    ps = "$ErrorActionPreference='SilentlyContinue';" + "$args | % { Get-AuthenticodeSignature -LiteralPath $_ } | Select Path,Status | ConvertTo-Json"
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps, *exes], capture_output=True, text=True, creationflags=0x08000000)
    try:
        rows = json.loads(r.stdout or "[]")
    except ValueError:
        return []
    rows = rows if isinstance(rows, list) else [rows]
    out = []
    for row in rows:
        status = row.get("Status")
        if status not in (0, "Valid") and row.get("Path"):
            out.append(Finding("autorun", f"Unsigned startup program ({exes.get(row['Path'], '?')})", row["Path"], 0,
                               risk="medium", selected=False))
    return out


# --------------------------------------------------------- Defender wrapper

def _ps(cmd: str, timeout: int = 120) -> str:
    r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True,
                       timeout=timeout, creationflags=0x08000000)
    return r.stdout.strip()


def defender_status() -> dict:
    out = _ps("Get-MpComputerStatus | Select AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,"
              "QuickScanEndTime | ConvertTo-Json")
    try:
        return json.loads(out)
    except ValueError:
        return {}


def antivirus_products() -> list[str]:
    """Names of antivirus products registered with Windows Security Center."""
    out = _ps("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
              "Select -Expand displayName | ConvertTo-Json")
    try:
        names = json.loads(out) if out else []
    except ValueError:
        return []
    return names if isinstance(names, list) else [names]


def defender_quick_scan() -> str:
    _ps("Start-MpScan -ScanType QuickScan", timeout=900)
    return _ps("Get-MpThreatDetection | Select -First 20 ThreatID,ProcessName,Resources | ConvertTo-Json") or "no detections"


def defender_update_signatures() -> str:
    return _ps("Update-MpSignature; 'done'", timeout=300)


# -------------------------------------------------------- URL / e-mail checks

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "gq", "tk", "ml", "cf", "work", "country", "kim", "loan"}
BRANDS = {"paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com", "google": "google.com",
          "amazon": "amazon.com", "netflix": "netflix.com", "facebook": "facebook.com", "instagram": "instagram.com",
          "dhl": "dhl.com", "fedex": "fedex.com", "chase": "chase.com", "wellsfargo": "wellsfargo.com"}


def domain_blocklist_path() -> Path:
    return data_dir() / "blocklist_domains.txt"


def load_domain_blocklist() -> set[str]:
    p = domain_blocklist_path()
    if not p.exists():
        p.write_text("# one domain per line\n", encoding="utf-8")
    return {ln.strip().lower() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")}


def check_url(url: str, blocklist: set[str] | None = None) -> dict:
    """Score a URL. Returns {score, verdict, reasons}. Heuristic, not a verdict from a threat feed."""
    blocklist = load_domain_blocklist() if blocklist is None else blocklist
    if "://" not in url:
        url = "http://" + url
    u = urlparse(url)
    host = (u.hostname or "").lower()
    reasons, score = [], 0
    if any(host == d or host.endswith("." + d) for d in blocklist):
        return dict(score=100, verdict="block", reasons=["domain is on your blocklist"])
    try:
        ipaddress.ip_address(host)
        reasons.append("raw IP address instead of a domain")
        score += 35
    except ValueError:
        pass
    if "@" in u.netloc:
        reasons.append("'@' in address hides the real host")
        score += 40
    if host.startswith("xn--") or ".xn--" in host:
        reasons.append("punycode (look-alike characters)")
        score += 30
    labels = host.split(".")
    if len(labels) > 4:
        reasons.append("unusually many subdomains")
        score += 15
    if labels[-1] in SUSPICIOUS_TLDS:
        reasons.append(f"high-abuse TLD .{labels[-1]}")
        score += 20
    registered = ".".join(labels[-2:])
    for key, real in BRANDS.items():
        if key in host and registered != real:
            reasons.append(f"mentions '{key}' but isn't {real}")
            score += 40
            break
    if u.scheme == "http" and re.search(r"(login|signin|verify|secure|account|update|password)", u.path + (u.query or ""), re.I):
        reasons.append("sign-in style page over plain HTTP")
        score += 20
    if len(url) > 200:
        reasons.append("very long URL")
        score += 10
    verdict = "block" if score >= 60 else "warn" if score >= 30 else "ok"
    return dict(score=min(score, 100), verdict=verdict, reasons=reasons or ["no red flags found"])


_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


def check_eml(path: str) -> dict:
    """Inspect a saved .eml for spoofing signs and risky links."""
    msg = email.message_from_string(Path(path).read_text(encoding="utf-8", errors="replace"), policy=policy.default)
    reasons, score = [], 0
    from_h = str(msg.get("From", ""))
    reply = str(msg.get("Reply-To", ""))
    m = re.search(r"<([^>]+)>", from_h)
    from_addr = (m.group(1) if m else from_h).lower()
    disp = from_h.split("<")[0].strip().strip('"').lower()
    from_dom = from_addr.rsplit("@", 1)[-1]
    auth = " ".join(msg.get_all("Authentication-Results", []) or []).lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(mech + r"=(fail|softfail|none)", auth):
            reasons.append(f"{mech.upper()} did not pass")
            score += 25
    if reply:
        rm = re.search(r"<([^>]+)>", reply)
        rdom = ((rm.group(1) if rm else reply).lower()).rsplit("@", 1)[-1]
        if rdom != from_dom:
            reasons.append(f"Reply-To domain ({rdom}) differs from sender ({from_dom})")
            score += 25
    for key, real in BRANDS.items():
        if key in disp and not from_dom.endswith(real):
            reasons.append(f"display name says '{key}' but mail is from {from_dom}")
            score += 40
            break
    body = msg.get_body(preferencelist=("html", "plain"))
    text = body.get_content() if body else ""
    bad_links = []
    for url in set(_URL_RE.findall(text)):
        r = check_url(url)
        if r["verdict"] != "ok":
            bad_links.append((url, r["verdict"]))
    if bad_links:
        reasons.append(f"{len(bad_links)} suspicious link(s)")
        score += 30
    verdict = "dangerous" if score >= 60 else "suspicious" if score >= 30 else "looks ok"
    return dict(score=min(score, 100), verdict=verdict, reasons=reasons or ["no red flags found"], links=bad_links)


# ------------------------------------------------------------ hosts blocking

HOSTS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
_HB, _HE = f"# >>> {brand.HOSTS_MARKER} BLOCK", f"# <<< {brand.HOSTS_MARKER} BLOCK"


def hosts_apply(domains: set[str] | None = None) -> int:
    if not is_admin():
        raise PermissionError("administrator rights are required to edit the hosts file")
    domains = domains if domains is not None else load_domain_blocklist()
    shutil.copy2(HOSTS, data_dir() / "hosts.backup")
    text = _strip_block(HOSTS.read_text(encoding="utf-8", errors="replace"))
    block = "\n".join([_HB] + [f"0.0.0.0 {d}" for d in sorted(domains)] + [_HE])
    HOSTS.write_text(text.rstrip("\n") + "\n" + block + "\n", encoding="utf-8")
    log_action("hosts-apply", f"{len(domains)} domains")
    return len(domains)


def hosts_remove() -> None:
    if not is_admin():
        raise PermissionError("administrator rights are required to edit the hosts file")
    HOSTS.write_text(_strip_block(HOSTS.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
    log_action("hosts-remove", "")


def _strip_block(text: str) -> str:
    s, e = text.find(_HB), text.find(_HE)
    return text if s == -1 or e == -1 else (text[:s] + text[e + len(_HE):]).strip("\n") + "\n"


# --------------------------------------------------------- sensitive-data guard

CANARY = ".pcforge_canary.txt"


class FolderGuard:
    """Polls protected folders and raises an alert on suspicious change.

    Detects: canary file touched/removed (ransomware tripwire), mass modification,
    mass deletion. It cannot say *which process* did it or block it; that needs a
    kernel driver. Alerts come through `on_alert(message)`.
    """

    def __init__(self, folders: list[str], on_alert, interval: float = 3.0, mass_threshold: int = 25):
        self.folders, self.on_alert, self.interval, self.mass = folders, on_alert, interval, mass_threshold
        self._stop = threading.Event()
        self._snap: dict[str, tuple[float, int]] = {}
        self._canary_text = f"{brand.NAME} canary file. Do not edit or delete.\n"
        self._thread: threading.Thread | None = None

    def _snapshot(self) -> dict[str, tuple[float, int]]:
        snap = {}
        for root in self.folders:
            for dp, _dn, files in os.walk(root):
                for fn in files:
                    p = os.path.join(dp, fn)
                    try:
                        st = os.stat(p)
                        snap[p] = (st.st_mtime, st.st_size)
                    except OSError:
                        pass
        return snap

    def start(self):
        for root in self.folders:
            c = os.path.join(root, CANARY)
            if not os.path.exists(c):
                Path(c).write_text(self._canary_text, encoding="utf-8")
        self._snap = self._snapshot()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="folder-guard")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.wait(self.interval):
            now = self._snapshot()
            changed = [p for p, v in now.items() if p in self._snap and self._snap[p] != v]
            gone = [p for p in self._snap if p not in now]
            for p in changed + gone:
                if os.path.basename(p) == CANARY:
                    self.on_alert(f"Canary file was {'deleted' if p in gone else 'modified'}: {p}  (possible ransomware)")
            if len(changed) >= self.mass:
                self.on_alert(f"{len(changed)} files changed within {self.interval:.0f}s in protected folders")
            if len(gone) >= self.mass:
                self.on_alert(f"{len(gone)} files disappeared within {self.interval:.0f}s from protected folders")
            self._snap = now
