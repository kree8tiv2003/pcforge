"""Smart RAM: watch memory pressure and trim idle working sets.

Trimming (EmptyWorkingSet) only asks Windows to page out memory a process isn't
actively using; nothing is killed and processes fault pages back in on demand.
"""
from __future__ import annotations

import ctypes
import threading
import time
from typing import Callable

import psutil

PROCESS_QUERY = 0x0400
PROCESS_SET_QUOTA = 0x0100


def usage() -> dict:
    vm = psutil.virtual_memory()
    return dict(total=vm.total, used=vm.total - vm.available, available=vm.available, percent=vm.percent)


def trim_working_sets() -> dict:
    k32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
    k32.OpenProcess.restype = ctypes.c_void_p
    before = psutil.virtual_memory().available
    trimmed = 0
    for pid in psutil.pids():
        if pid in (0, 4):
            continue
        h = k32.OpenProcess(PROCESS_QUERY | PROCESS_SET_QUOTA, False, pid)
        if not h:
            continue
        try:
            if psapi.EmptyWorkingSet(ctypes.c_void_p(h)):
                trimmed += 1
        finally:
            k32.CloseHandle(ctypes.c_void_p(h))
    time.sleep(0.5)
    after = psutil.virtual_memory().available
    return dict(processes=trimmed, freed=max(0, after - before), **usage())


class SmartRam:
    """Background monitor: trims when usage stays above `threshold` percent."""

    def __init__(self, threshold: int = 80, interval: float = 10.0, cooldown: float = 120.0,
                 on_trim: Callable[[dict], None] | None = None):
        self.threshold, self.interval, self.cooldown, self.on_trim = threshold, interval, cooldown, on_trim
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last = 0.0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="smart-ram")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.wait(self.interval):
            if psutil.virtual_memory().percent >= self.threshold and time.time() - self._last >= self.cooldown:
                result = trim_working_sets()
                self._last = time.time()
                if self.on_trim:
                    self.on_trim(result)
