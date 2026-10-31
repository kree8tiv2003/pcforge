"""AI Mode: one scan across every module, a 0-100 health score and a fix plan.

"AI" here means a rules engine over your machine's real measurements, not a model.
Only low-risk, pre-selected findings are included in the automatic plan; anything
risky stays a manual decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from . import cleaner, privacy, protection, ram, registry_cleaner, startup
from .safety import Finding, fmt_size, is_admin


@dataclass
class Step:
    name: str
    detail: str
    impact: int                       # points of health score this step recovers
    apply: Callable[[bool], str]      # apply(dry_run) -> human-readable result


@dataclass
class Report:
    score: int = 100
    notes: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)


def analyze(progress: Callable[[str], None] = lambda s: None) -> Report:
    rep = Report()

    progress("Scanning junk files")
    junk = [f for f in cleaner.scan_junk() if f.selected and not f.needs_admin]
    junk_bytes = sum(f.size for f in junk)
    if junk:
        pts = min(25, int(junk_bytes / (1 << 30) * 5) + 2)
        rep.score -= pts
        rep.steps.append(Step("Remove junk files", f"{len(junk)} items, {fmt_size(junk_bytes)}", pts,
                              lambda dry, j=junk: _clean_msg(cleaner.clean(j, dry))))

    progress("Checking shortcuts")
    sc = [f for f in cleaner.scan_shortcuts() if f.selected and not f.needs_admin]   # missing-icon ones stay manual
    if sc:
        rep.score -= min(5, len(sc))
        rep.steps.append(Step("Delete broken shortcuts", f"{len(sc)} shortcuts", min(5, len(sc)),
                              lambda dry, s=sc: _clean_msg(cleaner.clean_shortcuts(s, dry))))

    progress("Checking registry")
    reg = [f for f in registry_cleaner.scan_registry(include_risky=False) if f.selected and not f.needs_admin]
    if reg:
        pts = min(15, 2 + len(reg) // 5)
        rep.score -= pts
        rep.steps.append(Step("Fix registry leftovers (backed up first)", f"{len(reg)} entries", pts,
                              lambda dry, r=reg: _clean_msg(registry_cleaner.fix_registry(r, dry), size=False)))

    progress("Checking startup items")
    heavy = [i for i in startup.list_startup() if i.enabled and i.recommend_disable and not i.needs_admin
             and i.kind != "service"]            # services are a manual decision
    if heavy:
        pts = min(15, 3 * len(heavy))
        rep.score -= pts
        names = ", ".join(i.name for i in heavy[:4]) + ("…" if len(heavy) > 4 else "")
        rep.steps.append(Step("Disable non-essential startup items", names, pts,
                              lambda dry, h=heavy: f"{len(h)} items " + ("would be disabled" if dry else
                                                                         f"disabled ({sum(startup.set_enabled(i, False) for i in h)} ok)")))

    progress("Checking browser caches")
    cache = [f for f in privacy.scan_browsers() if f.selected and not f.meta.get("browser_running")]
    if sum(f.size for f in cache) < (1 << 20):
        cache = []                                   # not worth a step for under 1 MB
    if cache:
        b = sum(f.size for f in cache)
        rep.score -= min(8, int(b / (1 << 28)) + 1)
        rep.steps.append(Step("Clear browser caches", f"{len(cache)} caches, {fmt_size(b)}", min(8, int(b / (1 << 28)) + 1),
                              lambda dry, c=cache: _clean_msg(privacy.sweep(c, dry))))

    progress("Checking memory")
    mem = ram.usage()
    if mem["percent"] >= 70:
        pts = 10 if mem["percent"] >= 85 else 5
        rep.score -= pts
        rep.steps.append(Step("Free idle memory", f"{mem['percent']:.0f}% RAM in use", pts,
                              lambda dry: "would trim working sets" if dry else
                              f"freed {fmt_size(ram.trim_working_sets()['freed'])}"))

    progress("Checking protection")
    st = protection.defender_status()
    if st and not st.get("RealTimeProtectionEnabled", True):
        others = [n for n in protection.antivirus_products() if "defender" not in n.lower()]
        if others:
            rep.notes.append(f"Real-time protection is handled by {', '.join(others)} (Defender is standing by).")
        else:
            rep.score -= 20
            rep.notes.append("No real-time antivirus is active. Turn Windows Defender on in Windows Security (not changed automatically).")
    threats = protection.scan_threats()
    if threats:
        rep.score -= min(30, 10 * len(threats))
        rep.notes.append(f"{len(threats)} suspicious file(s) found. Review them in Protection; they were not touched.")

    if not is_admin():
        rep.notes.append("Not running as administrator: system-wide junk and HKLM registry items were skipped.")
    rep.score = max(0, rep.score)
    return rep


def execute(rep: Report, dry_run: bool = True, progress: Callable[[str], None] = lambda s: None) -> list[str]:
    out = []
    for s in rep.steps:
        progress(s.name)
        out.append(f"{s.name}: {s.apply(dry_run)}")
    return out


def _clean_msg(res, size: bool = True) -> str:
    base = f"{res.removed} done" + (f", {fmt_size(res.freed)}" if size else "")
    return base + (f", {len(res.skipped)} skipped" if res.skipped else "")
