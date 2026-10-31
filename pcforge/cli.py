"""Command line front end. Destructive commands are dry runs unless you pass --apply."""
from __future__ import annotations

import argparse
import sys

from . import ai_mode, brand, cleaner, hardening, privacy, protection, ram, registry_cleaner, startup, toolbox, turbo
from .safety import fmt_size, is_admin


def _show_result(res, label="done"):
    print(f"  {label}: {res.removed} item(s), {fmt_size(res.freed)}")
    for p, why in res.skipped[:10]:
        print(f"  skipped {p}: {why}")
    if len(res.skipped) > 10:
        print(f"  ... and {len(res.skipped) - 10} more skipped")


def _mode(args) -> bool:
    dry = not args.apply
    print("[APPLY]" if args.apply else "[dry run - add --apply to make changes]")
    return dry


def cmd_ai(a):
    rep = ai_mode.analyze(lambda s: print(f"  ... {s}", file=sys.stderr))
    print(f"\nHealth score: {rep.score}/100")
    for n in rep.notes:
        print(f"  note: {n}")
    for s in rep.steps:
        print(f"  [{s.impact:+d}] {s.name} - {s.detail}")
    if rep.steps:
        dry = _mode(a)
        for line in ai_mode.execute(rep, dry):
            print("  " + line)


def cmd_clean(a):
    f = cleaner.scan_junk()
    for label, (n, b) in sorted(cleaner.summarize(f).items(), key=lambda kv: -kv[1][1]):
        print(f"  {fmt_size(b):>10}  {n:>5}  {label}")
    print(f"  total {fmt_size(sum(x.size for x in f))}")
    print("[APPLY]" if a.apply else "[dry run - add --apply to delete]")
    _show_result(cleaner.clean([x for x in f if x.selected], not a.apply), "freed" if a.apply else "would free")


def cmd_shortcuts(a):
    f = cleaner.scan_shortcuts()
    for x in f:
        print(f"  [{x.label}] {x.path}  ->  {x.meta.get('target') or x.meta.get('icon')}")
    broken = sum(1 for x in f if x.category == "shortcut")
    print(f"  {len(f)} shortcut problem(s): {broken} missing target, {len(f) - broken} missing icon (icon ones are not pre-selected)")
    if f and a.apply:
        _show_result(cleaner.clean_shortcuts(f, False))


def cmd_leftovers(a):
    f = cleaner.scan_leftover_folders()
    for x in f:
        print(f"  {fmt_size(x.size):>10}  {x.path}")
    print(f"  {len(f)} candidate folder(s). Review before using --apply.")
    if f and a.apply:
        _show_result(cleaner.clean_leftovers(f, False))


def cmd_registry(a):
    if a.restore:
        n = registry_cleaner.restore_backup(a.restore)
        print(f"restored {n} backup file(s)")
        return
    f = registry_cleaner.scan_registry()
    for x in f:
        print(f"  [{x.label}] {x.path}  {x.meta.get('detail', '')}" + ("  (needs admin)" if x.needs_admin else ""))
    print(f"  {len(f)} issue(s)")
    if f and a.apply:
        _show_result(registry_cleaner.fix_registry(f, False), "fixed")
        print(f"  backups: {registry_cleaner.list_backups()[-1] if registry_cleaner.list_backups() else 'none'}")


def cmd_startup(a):
    items = startup.list_startup()
    for i, it in enumerate(items):
        flag = "ON " if it.enabled else "off"
        hint = "  <- suggested to disable" if it.enabled and it.recommend_disable else ""
        print(f"  {i:>2} [{flag}] {it.name[:40]:<40} {it.source}{hint}")
    if a.disable is not None or a.enable is not None:
        idx, want = (a.disable, False) if a.disable is not None else (a.enable, True)
        ok = startup.set_enabled(items[idx], want)
        print("  changed" if ok else "  failed (needs admin?)")


def cmd_selftest(a):
    """Proves the pieces updating depends on work inside this build (also inside the packaged exe)."""
    import base64
    import ssl

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from . import updater
    key = Ed25519PrivateKey.generate()
    pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    m = {"version": "9.9.9", "sha256": "0" * 64, "size": 1, "url": "https://x/y"}
    m["signature"] = base64.b64encode(key.sign(updater.signed_payload(m))).decode()
    updater.verify_signature(m, pub)
    try:
        m["url"] = "https://evil/y"
        updater.verify_signature(m, pub)
        print("FAIL tampered manifest accepted")
        return
    except updater.UpdateError:
        pass
    certs = ssl.create_default_context().cert_store_stats()
    print(f"signature check ok | tamper detection ok | https certificates loaded: {certs.get('x509_ca', 0) + certs.get('x509', 0)} "
          f"| public key configured: {bool(brand.UPDATE_PUBLIC_KEY)} | update address set: {bool(brand.UPDATE_MANIFEST_URL)}")


def cmd_update(a):
    from . import updater
    try:
        info = updater.check()
    except updater.UpdateError as e:
        print(" ", e)
        return
    if info is None:
        print(f"  You're up to date ({brand.VERSION}).")
        return
    print(f"  Version {info.version} is available ({fmt_size(info.size)}).\n  {info.notes}")
    if a.apply:
        path = updater.download(info, lambda got, total: print(f"\r  downloading {got * 100 // max(total, 1)}%", end=""))
        print()
        updater.apply_and_restart(path)
        print("  installing; PCForge will restart")
    else:
        print("  Add --apply to download and install it.")


def cmd_ignore(a):
    from . import safety
    if a.add:
        safety.add_ignore(a.add)
    if a.remove:
        safety.remove_ignore(a.remove)
    for i in safety.load_ignore():
        print("  ", i)


def cmd_restorepoint(a):
    from . import safety
    ok, why = safety.create_restore_point() if a.apply else (False, "dry run - add --apply (needs administrator)")
    print(" ", "created" if ok else why)


def cmd_turbo(a):
    if a.action == "off":
        print(f"resumed {turbo.restore()} process(es)")
        return
    done = turbo.enable(a.mode, a.extra, dry_run=not a.apply)
    for r in done:
        print(f"  {r['name']} (pid {r['pid']})")
    print(f"  {len(done)} process(es) " + ("suspended" if a.apply else "would be suspended; add --apply"))


def cmd_ram(a):
    u = ram.usage()
    print(f"  RAM {fmt_size(u['used'])} / {fmt_size(u['total'])} ({u['percent']:.0f}%)")
    if a.trim:
        r = ram.trim_working_sets()
        print(f"  trimmed {r['processes']} processes, freed {fmt_size(r['freed'])}")


def cmd_privacy(a):
    f = privacy.scan_browsers() + privacy.scan_windows_traces()
    pick = [x for x in f if x.selected or x.category.split("-")[-1] in (a.include or [])]
    for x in f:
        mark = "x" if x in pick else " "
        busy = " (browser open)" if x.meta.get("browser_running") else ""
        print(f"  [{mark}] {fmt_size(x.size):>10}  {x.label}{busy}")
    print("  include more with --include history cookies passwords autofill")
    if a.apply:
        _show_result(privacy.sweep(pick, False))


def cmd_harden(a):
    if a.revert:
        print(hardening.revert())
    elif a.apply:
        print("Firefox profiles:", hardening.apply_firefox(), "| Chromium policies:", hardening.apply_chromium())
    else:
        print("Would set Firefox fingerprint-resistance prefs and Chrome/Edge privacy policies. Add --apply.")


def cmd_protect(a):
    if a.defender:
        print(protection.defender_status())
        return
    f = protection.scan_threats() + protection.unsigned_autorun_targets()
    for x in f:
        print(f"  [{x.risk}] {x.path}\n         {x.label}")
    print(f"  {len(f)} finding(s). Nothing was changed.")
    if a.quarantine:
        print("quarantined to", protection.quarantine(a.quarantine))


def cmd_url(a):
    r = protection.check_url(a.url)
    print(f"  {r['verdict'].upper()} ({r['score']}/100)")
    for x in r["reasons"]:
        print("   -", x)


def cmd_eml(a):
    r = protection.check_eml(a.file)
    print(f"  {r['verdict'].upper()} ({r['score']}/100)")
    for x in r["reasons"]:
        print("   -", x)
    for u, v in r["links"]:
        print(f"   link [{v}] {u}")


def cmd_tools(a):
    if a.tool == "large":
        for size, p in toolbox.find_large_files(a.paths or [r"C:\Users"], a.min_mb, 30):
            print(f"  {fmt_size(size):>10}  {p}")
    elif a.tool == "shred":
        for p in a.paths:
            ok = toolbox.shred_file(p, dry_run=not a.apply)
            print(("  shredded " if a.apply else "  would shred ") + p if ok else f"  cannot shred {p}")
    elif a.tool == "dns":
        for label, ip, ms in toolbox.dns_benchmark():
            print(f"  {label:<12} {ip:<16} {'timeout' if ms is None else f'{ms:.0f} ms'}")
        if a.apply:
            print("  flushed" if toolbox.flush_dns() else "  flush failed")
    elif a.tool == "updates":
        if not toolbox.winget_available():
            print("  winget not found")
            return
        rows = toolbox.outdated_software()
        for r in rows:
            print(f"  {r['name']:<40} {r['version']} -> {r['available']}  ({r['id']})")
        print(f"  {len(rows)} update(s) available")
        if a.apply:
            for r in rows:
                print("  upgrading", r["id"], "ok" if toolbox.upgrade_software(r["id"]) else "failed")
    elif a.tool == "winfix":
        print(toolbox.dism_check())
        if a.apply:
            print(toolbox.run_sfc())
    elif a.tool == "disks":
        for d in toolbox.disk_summary():
            print(f"  {d['drive']:<5} {fmt_size(d['free'])} free of {fmt_size(d['total'])} ({d['percent']:.0f}% used)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=brand.NAME.lower(), description=f"{brand.NAME} {brand.VERSION} - {brand.TAGLINE}")
    sub = p.add_subparsers(dest="cmd")

    def add(name, fn, **kw):
        s = sub.add_parser(name, **kw)
        s.add_argument("--apply", action="store_true", help="actually make changes (default is a dry run)")
        s.set_defaults(fn=fn)
        return s

    add("gui", lambda a: __import__("pcforge.gui", fromlist=["run"]).run(), help="open the desktop app")
    add("ai", cmd_ai, help="AI Mode: scan everything, score, plan, fix")
    add("clean", cmd_clean, help="junk file cleaner")
    add("shortcuts", cmd_shortcuts, help="broken shortcut finder")
    add("leftovers", cmd_leftovers, help="empty program folders (review first)")
    s = add("registry", cmd_registry, help="registry cleaner (backs up first)")
    s.add_argument("--restore", help="folder of .reg backups to re-import")
    s = add("startup", cmd_startup, help="startup optimizer")
    s.add_argument("--disable", type=int, metavar="N")
    s.add_argument("--enable", type=int, metavar="N")
    add("selftest", cmd_selftest, help="check that update signing/https work in this build")
    add("update", cmd_update, help="check for (and with --apply install) a newer PCForge")
    s = add("ignore", cmd_ignore, help="manage the ignore list (paths/keys that scans skip)")
    s.add_argument("--add")
    s.add_argument("--remove")
    add("restorepoint", cmd_restorepoint, help="create a System Restore point (administrator)")
    s = add("turbo", cmd_turbo, help="Turbo Boost")
    s.add_argument("action", choices=["on", "off"])
    s.add_argument("--mode", choices=["work", "game"], default="work")
    s.add_argument("--extra", nargs="*", default=[], help="extra process-name regexes to suspend")
    s = add("ram", cmd_ram, help="Smart RAM")
    s.add_argument("--trim", action="store_true")
    s = add("privacy", cmd_privacy, help="privacy sweeper")
    s.add_argument("--include", nargs="*", choices=["history", "cookies", "passwords", "autofill"])
    s = add("harden", cmd_harden, help="browser tracking/fingerprint hardening")
    s.add_argument("--revert", action="store_true")
    s = add("protect", cmd_protect, help="threat scan (read-only) and Defender status")
    s.add_argument("--defender", action="store_true")
    s.add_argument("--quarantine", metavar="FILE")
    s = add("url", cmd_url, help="check a link")
    s.add_argument("url")
    s = add("eml", cmd_eml, help="check a saved e-mail (.eml)")
    s.add_argument("file")
    s = add("tools", cmd_tools, help="toolbox")
    s.add_argument("tool", choices=["large", "shred", "dns", "updates", "winfix", "disks"])
    s.add_argument("paths", nargs="*")
    s.add_argument("--min-mb", type=int, default=100)
    return p


def main(argv=None) -> int:
    p = build_parser()
    a = p.parse_args(argv)
    if not getattr(a, "fn", None):
        p.print_help()
        return 0
    if not is_admin() and a.cmd in ("registry", "clean", "leftovers"):
        print("note: not running as administrator; system-wide items will be skipped.", file=sys.stderr)
    a.fn(a)
    return 0
