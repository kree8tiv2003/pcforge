"""Browser tracking/fingerprint hardening.

Honest scope: this shrinks what sites can learn (fingerprint resistance, third-party
cookie blocking, WebRTC IP leak prevention). It does not spoof or randomise an
identity the way a dedicated anti-detect browser does. Everything applied here is
recorded so `revert()` restores the previous state.
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import winreg
from pathlib import Path

from .safety import data_dir, log_action

BEGIN, END = "// >>> PCFORGE BEGIN", "// <<< PCFORGE END"

FIREFOX_PREFS = {
    "privacy.resistFingerprinting": "true",
    "privacy.firstparty.isolate": "true",
    "privacy.trackingprotection.enabled": "true",
    "privacy.trackingprotection.fingerprinting.enabled": "true",
    "privacy.trackingprotection.cryptomining.enabled": "true",
    "network.cookie.cookieBehavior": "5",
    "media.peerconnection.ice.default_address_only": "true",
    "media.peerconnection.ice.no_host": "true",
    "privacy.donottrackheader.enabled": "true",
    "geo.enabled": "false",
    "webgl.disabled": "false",
    "beacon.enabled": "false",
}

# registry policy values per Chromium browser (HKCU\Software\Policies\<path>)
CHROMIUM_POLICIES = {
    "Google Chrome": (r"Software\Policies\Google\Chrome",
                      {"BlockThirdPartyCookies": 1, "WebRtcIPHandlingPolicy": "disable_non_proxied_udp",
                       "PrivacySandboxAdTopicsEnabled": 0, "PrivacySandboxAdMeasurementEnabled": 0,
                       "PrivacySandboxSiteEnabledAdsEnabled": 0}),
    "Microsoft Edge": (r"Software\Policies\Microsoft\Edge",
                       {"BlockThirdPartyCookies": 1, "WebRtcIPHandlingPolicy": "disable_non_proxied_udp",
                        "TrackingPrevention": 3, "ConfigureDoNotTrack": 1}),
}


def _state_path():
    return data_dir() / "hardening_state.json"


def _load():
    try:
        return json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"policies": {}, "userjs": []}


def firefox_profiles() -> list[str]:
    root = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    return [p for p in glob.glob(os.path.join(root, "*")) if os.path.isdir(p)]


def _userjs_block() -> str:
    lines = [BEGIN] + [f'user_pref("{k}", {v});' for k, v in FIREFOX_PREFS.items()] + [END]
    return "\n".join(lines) + "\n"


def apply_firefox() -> int:
    state, n = _load(), 0
    for prof in firefox_profiles():
        path = os.path.join(prof, "user.js")
        existing = Path(path).read_text(encoding="utf-8") if os.path.exists(path) else ""
        if BEGIN in existing:
            continue
        if existing:
            shutil.copy2(path, path + ".pcforge.bak")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(existing + ("\n" if existing and not existing.endswith("\n") else "") + _userjs_block())
        state["userjs"].append(path)
        n += 1
    _state_path().write_text(json.dumps(state), encoding="utf-8")
    log_action("harden-firefox", f"{n} profiles")
    return n


def apply_chromium() -> list[str]:
    state, done = _load(), []
    for name, (sub, values) in CHROMIUM_POLICIES.items():
        prior = state["policies"].setdefault(name, {})
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, sub, 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
            for vname, val in values.items():
                if vname not in prior:
                    try:
                        prior[vname] = list(winreg.QueryValueEx(k, vname))  # remember old (value, type)
                    except OSError:
                        prior[vname] = None
                typ = winreg.REG_DWORD if isinstance(val, int) else winreg.REG_SZ
                winreg.SetValueEx(k, vname, 0, typ, val)
        done.append(name)
    _state_path().write_text(json.dumps(state), encoding="utf-8")
    log_action("harden-chromium", ",".join(done))
    return done


def revert() -> dict:
    state = _load()
    removed_js = 0
    for path in state.get("userjs", []):
        if not os.path.exists(path):
            continue
        text = Path(path).read_text(encoding="utf-8")
        s, e = text.find(BEGIN), text.find(END)
        if s != -1 and e != -1:
            text = (text[:s] + text[e + len(END):]).strip("\n")
            if text.strip():
                Path(path).write_text(text + "\n", encoding="utf-8")
            else:
                os.remove(path)
            removed_js += 1
    restored = 0
    for name, prior in state.get("policies", {}).items():
        sub = CHROMIUM_POLICIES[name][0]
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0, winreg.KEY_WRITE) as k:
                for vname, old in prior.items():
                    if old is None:
                        try:
                            winreg.DeleteValue(k, vname)
                        except OSError:
                            pass
                    else:
                        winreg.SetValueEx(k, vname, 0, old[1], old[0])
                    restored += 1
        except OSError:
            continue
    try:
        _state_path().unlink()
    except OSError:
        pass
    log_action("harden-revert", f"js={removed_js} policies={restored}")
    return dict(firefox_profiles=removed_js, policy_values=restored)
