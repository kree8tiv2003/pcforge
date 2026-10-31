"""Small persistent settings file (JSON in the PCForge data folder)."""
from __future__ import annotations

import json

from .safety import data_dir

DEFAULTS = {
    "auto_check": True,        # look for a new version when the app starts (at most once a day)
    "auto_download": False,    # download quietly; you still click Restart to install
    "last_check": 0.0,
    "skipped_version": "",
}


def _path():
    return data_dir() / "settings.json"


def load() -> dict:
    try:
        stored = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        stored = {}
    return {**DEFAULTS, **{k: v for k, v in stored.items() if k in DEFAULTS}}


def save(values: dict) -> None:
    _path().write_text(json.dumps({**load(), **values}, indent=1), encoding="utf-8")


def get(key: str):
    return load()[key]


def set_(key: str, value) -> None:
    save({key: value})
