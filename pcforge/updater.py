"""Self-update: check a signed manifest, download, verify, swap the exe and restart.

Safety rules:
  - The manifest must carry an Ed25519 signature over (version|sha256|size|url) made with
    your private key; the matching public key is baked into brand.UPDATE_PUBLIC_KEY.
    No key configured, or a bad signature, means no update. (Fails closed.)
  - Downloads must be https (http only for 127.0.0.1 in tests), match the signed size and SHA-256.
  - The old exe is kept as PCForge.exe.old and put back if the swap fails.
  - Nothing is installed without you clicking; the update only ever replaces the PCForge exe itself.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from . import brand, settings
from .safety import data_dir, log_action

MAX_EXE_BYTES = 250 * 1024 * 1024
CHECK_EVERY_S = 24 * 3600


class UpdateError(Exception):
    pass


@dataclass
class UpdateInfo:
    version: str
    url: str
    sha256: str
    size: int
    notes: str = ""


def parse_version(v: str) -> tuple[int, ...]:
    nums = tuple(int(x) for x in re.findall(r"\d+", v or ""))
    if not nums:
        raise UpdateError(f"bad version: {v!r}")
    return nums


def is_newer(candidate: str, current: str) -> bool:
    a, b = parse_version(candidate), parse_version(current)
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) > b + (0,) * (n - len(b))


def signed_payload(m: dict) -> bytes:
    return f"{m['version']}|{m['sha256'].lower()}|{int(m['size'])}|{m['url']}".encode()


def verify_signature(manifest: dict, public_key_b64: str) -> None:
    if not public_key_b64:
        raise UpdateError("updates are not set up in this build (no signing key)")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        key.verify(base64.b64decode(manifest["signature"]), signed_payload(manifest))
    except (InvalidSignature, KeyError, ValueError) as e:
        raise UpdateError("the update's signature is not valid, so it was ignored") from e


def _open(url: str, timeout: float, allow_loopback: bool):
    u = urlparse(url)
    loop = allow_loopback and u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost")
    if u.scheme != "https" and not loop:
        raise UpdateError("updates must be downloaded over https")
    resp = urlopen(Request(url, headers={"User-Agent": f"{brand.NAME}/{brand.VERSION}"}), timeout=timeout)
    final = urlparse(resp.geturl())
    if final.scheme != "https" and not (allow_loopback and final.hostname in ("127.0.0.1", "localhost")):
        resp.close()
        raise UpdateError("the update server redirected to an insecure address")
    return resp


def check(manifest_url: str | None = None, current: str | None = None, public_key: str | None = None,
          timeout: float = 10, allow_loopback: bool = False) -> UpdateInfo | None:
    """Return the newer version's info, or None if you're up to date. Raises UpdateError on any problem."""
    url = brand.UPDATE_MANIFEST_URL if manifest_url is None else manifest_url
    if not url:
        raise UpdateError("no update server is configured yet")
    try:
        with _open(url, timeout, allow_loopback) as resp:
            manifest = json.loads(resp.read(65536).decode("utf-8"))
    except (OSError, ValueError) as e:
        raise UpdateError(f"could not reach the update server ({type(e).__name__})") from e
    verify_signature(manifest, brand.UPDATE_PUBLIC_KEY if public_key is None else public_key)
    if not (0 < int(manifest["size"]) <= MAX_EXE_BYTES) or not re.fullmatch(r"[0-9a-fA-F]{64}", manifest["sha256"]):
        raise UpdateError("the update description is malformed")
    settings.set_("last_check", time.time())
    if not is_newer(manifest["version"], brand.VERSION if current is None else current):
        return None
    return UpdateInfo(manifest["version"], manifest["url"], manifest["sha256"].lower(), int(manifest["size"]),
                      str(manifest.get("notes", ""))[:2000])


def due() -> bool:
    s = settings.load()
    return s["auto_check"] and time.time() - float(s["last_check"]) >= CHECK_EVERY_S


def download(info: UpdateInfo, progress=None, dest_dir: Path | None = None, timeout: float = 30,
             allow_loopback: bool = False) -> Path:
    """Download to the PCForge data folder and verify size + SHA-256 before returning the path."""
    dest_dir = dest_dir or (data_dir() / "updates")
    dest_dir.mkdir(parents=True, exist_ok=True)
    final = dest_dir / f"PCForge-{info.version}.exe"
    part = final.with_suffix(".part")
    h, got = hashlib.sha256(), 0
    try:
        with _open(info.url, timeout, allow_loopback) as resp, open(part, "wb") as out:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                got += len(chunk)
                if got > info.size:
                    raise UpdateError("the download is larger than announced")
                h.update(chunk)
                out.write(chunk)
                if progress:
                    progress(got, info.size)
    except OSError as e:
        part.unlink(missing_ok=True)
        raise UpdateError(f"download failed ({type(e).__name__})") from e
    if got != info.size or h.hexdigest() != info.sha256:
        part.unlink(missing_ok=True)
        raise UpdateError("the download did not match its signed fingerprint, so it was discarded")
    final.unlink(missing_ok=True)
    part.rename(final)
    log_action("update-downloaded", info.version)
    return final


def downloaded_update() -> tuple[str, Path] | None:
    """A verified download waiting to be installed (the newest one), if any."""
    d = data_dir() / "updates"
    best = None
    for p in d.glob("PCForge-*.exe") if d.exists() else []:
        v = p.stem.split("-", 1)[1]
        try:
            if is_newer(v, brand.VERSION) and (best is None or is_newer(v, best[0])):
                best = (v, p)
        except UpdateError:
            continue
    return best


def build_swap_script(pid: int, new: Path, target: Path, log: Path, relaunch: bool = True, swap_tries: int = 30) -> str:
    """cmd script: wait for us to exit, keep the old exe as .old, move the new one in, restart; undo on failure."""
    backup = Path(str(target) + ".old")
    return f"""@echo off
setlocal
set "NEW={new}"
set "TARGET={target}"
set "BACKUP={backup}"
set "LOG={log}"
set /a tries=0
:wait
tasklist /FI "PID eq {pid}" 2>NUL | find "{pid}" >NUL
if not errorlevel 1 (
  set /a tries+=1
  if %tries% GTR 60 goto fail
  ping -n 2 127.0.0.1 >NUL
  goto wait
)
set /a tries=0
:swap
if exist "%BACKUP%" del /f /q "%BACKUP%" >NUL 2>&1
move /y "%TARGET%" "%BACKUP%" >NUL 2>&1
if errorlevel 1 (
  set /a tries+=1
  if %tries% GTR {swap_tries} goto fail
  ping -n 2 127.0.0.1 >NUL
  goto swap
)
move /y "%NEW%" "%TARGET%" >NUL 2>&1
if errorlevel 1 (
  move /y "%BACKUP%" "%TARGET%" >NUL 2>&1
  goto fail
)
echo ok> "%LOG%"
{'start "" "%TARGET%"' if relaunch else 'rem relaunch disabled'}
goto end
:fail
echo failed> "%LOG%"
if exist "%TARGET%" {'start "" "%TARGET%"' if relaunch else 'rem relaunch disabled'}
:end
(goto) 2>NUL & del /f /q "%~f0"
"""


def apply_and_restart(new: Path, target: Path | None = None, pid: int | None = None, relaunch: bool = True) -> None:
    """Start the swap script in its own hidden console. The caller must exit right after this returns.

    Do NOT add DETACHED_PROCESS here: a console-less cmd.exe silently fails to run the script's
    tasklist/find/ping steps (verified), so the update would never finish.
    """
    if not getattr(sys, "frozen", False) and target is None:
        raise UpdateError("updates can only be installed into the packaged PCForge.exe")
    target = target or Path(sys.executable)
    script = data_dir() / "apply_update.cmd"
    script.write_text(build_swap_script(pid or os.getpid(), new, target, data_dir() / "update_result.txt", relaunch), encoding="utf-8")
    flags = 0x08000000 | 0x00000200                    # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    # A packaged exe that starts another copy of itself inherits its parent's temp-folder settings, and the
    # relaunched copy then dies silently once the parent cleans up. This tells the new copy to start fresh.
    env = {**os.environ, "PYINSTALLER_RESET_ENVIRONMENT": "1"}
    env.pop("_MEIPASS2", None)
    subprocess.Popen(["cmd", "/c", str(script)], creationflags=flags, close_fds=True, env=env)
    log_action("update-applied", f"{target} <- {new.name}")


def last_result() -> str | None:
    p = data_dir() / "update_result.txt"
    try:
        text = p.read_text(encoding="utf-8").strip()
        p.unlink(missing_ok=True)
        return text
    except OSError:
        return None
