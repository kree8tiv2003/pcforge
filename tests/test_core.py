import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
# Keep test activity out of the real PCForge log and data folders.
os.environ["LOCALAPPDATA"] = tempfile.mkdtemp(prefix="pcforge-test-")

from pcforge import (ai_mode, cleaner, hardening, history, protection, registry_cleaner, report, safety,  # noqa: E402
                     toolbox, turbo)


def make_lnk(path, target):
    base = target.encode("mbcs") + b"\0"
    info = struct.pack("<IIIIIII", 28 + len(base) + 1, 28, 1, 0, 28, 0, 28 + len(base)) + base + b"\0"
    header = struct.pack("<I", 0x4C) + b"\0" * 16 + struct.pack("<I", 0x2) + b"\0" * (0x4C - 24)
    Path(path).write_bytes(header + info)


class SafeDelete(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "root")
        os.makedirs(os.path.join(self.root, "sub"))
        Path(self.root, "sub", "a.txt").write_bytes(b"x" * 100)
        self.outside = os.path.join(self.tmp, "outside.txt")
        Path(self.outside).write_bytes(b"keep")

    def test_dry_run_keeps_files_and_reports_size(self):
        freed, err = safety.delete_path(os.path.join(self.root, "sub"), [self.root], dry_run=True)
        self.assertEqual((freed, err), (100, None))
        self.assertTrue(os.path.exists(os.path.join(self.root, "sub", "a.txt")))

    def test_deletes_inside_root(self):
        freed, err = safety.delete_path(os.path.join(self.root, "sub"), [self.root], dry_run=False)
        self.assertEqual(freed, 100)
        self.assertFalse(os.path.exists(os.path.join(self.root, "sub")))

    def test_refuses_outside_and_root_itself(self):
        self.assertEqual(safety.delete_path(self.outside, [self.root], False)[1], "outside allowed roots")
        self.assertEqual(safety.delete_path(self.root, [self.root], False)[1], "outside allowed roots")
        self.assertTrue(os.path.exists(self.outside) and os.path.isdir(self.root))

    def test_dotdot_escape_is_refused(self):
        sneaky = os.path.join(self.root, "..", "outside.txt")
        self.assertEqual(safety.delete_path(sneaky, [self.root], False)[1], "outside allowed roots")
        self.assertTrue(os.path.exists(self.outside))

    @unittest.skipUnless(os.name == "nt", "junctions are Windows-only")
    def test_junction_is_not_followed(self):
        target = os.path.join(self.tmp, "precious")
        os.makedirs(target)
        Path(target, "doc.txt").write_text("important")
        junction = os.path.join(self.root, "link")
        subprocess.run(["cmd", "/c", "mklink", "/J", junction, target], capture_output=True, check=True)
        safety.delete_path(junction, [self.root], dry_run=False)
        self.assertFalse(os.path.exists(junction))
        self.assertTrue(os.path.exists(os.path.join(target, "doc.txt")), "target of junction must survive")


class Shortcuts(unittest.TestCase):
    def test_lnk_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.lnk")
            make_lnk(p, r"C:\definitely\not\here.exe")
            self.assertEqual(cleaner.parse_lnk_target(p), r"C:\definitely\not\here.exe")

    def test_icon_location_is_read_from_string_data(self):
        icon = r"C:\gone\app.ico,0"
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.lnk")
            base = b"C:\\here\\a.exe\0"
            info = struct.pack("<IIIIIII", 28 + len(base) + 1, 28, 1, 0, 28, 0, 28 + len(base)) + base + b"\0"
            flags = 0x2 | 0x40 | 0x80          # HasLinkInfo | HasIconLocation | IsUnicode
            header = struct.pack("<I", 0x4C) + b"\0" * 16 + struct.pack("<I", flags) + b"\0" * (0x4C - 24)
            Path(p).write_bytes(header + info + struct.pack("<H", len(icon)) + icon.encode("utf-16le"))
            parsed = cleaner.parse_lnk(p)
            self.assertEqual(parsed["target"], r"C:\here\a.exe")
            self.assertEqual(cleaner._icon_file(parsed["icon"]), r"C:\gone\app.ico")
        self.assertEqual(cleaner._icon_file(r"%SystemRoot%\system32\shell32.dll,-15"),
                         os.path.expandvars(r"%SystemRoot%\system32\shell32.dll"))

    def test_garbage_lnk_is_unknown_not_broken(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.lnk")
            Path(p).write_bytes(b"not a shortcut")
            self.assertIsNone(cleaner.parse_lnk_target(p))


class Registry(unittest.TestCase):
    def test_command_exe(self):
        self.assertEqual(registry_cleaner.command_exe('"C:\\Program Files\\A B\\a.exe" /s'), r"C:\Program Files\A B\a.exe")
        self.assertEqual(registry_cleaner.command_exe(r"C:\Program Files\A\a.exe -x"), r"C:\Program Files\A\a.exe")
        self.assertIsNone(registry_cleaner.command_exe("MsiExec /X{123}"))
        self.assertIsNone(registry_cleaner.command_exe(""))

    def test_exe_followed_by_slash_switch_and_windows_paths(self):
        self.assertEqual(registry_cleaner.command_exe(r"C:\A B\app.exe/Automation"), r"C:\A B\app.exe")
        self.assertFalse(registry_cleaner.definitely_missing(r"C:\Windows\System32\nothing_here.dll"),
                         "files inside the Windows folder are never judged")

    def test_missing_is_conservative(self):
        self.assertTrue(registry_cleaner.definitely_missing(r"C:\no\such\thing.exe"))
        self.assertFalse(registry_cleaner.definitely_missing(r"relative\thing.exe"))
        self.assertFalse(registry_cleaner.definitely_missing(r"\\server\share\a.exe"))
        self.assertFalse(registry_cleaner.definitely_missing(r"Z:\maybe\unplugged.exe") and not os.path.exists("Z:\\"))
        self.assertFalse(registry_cleaner.definitely_missing(sys.executable))


class RegistryFixLive(unittest.TestCase):
    """Touches only HKCU\\Software\\PCForgeTest, created and removed by the test."""
    SUB = r"Software\PCForgeTest\Run"

    def test_backup_delete_restore(self):
        import winreg
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.SUB)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.SUB, 0, winreg.KEY_WRITE) as k:
            winreg.SetValueEx(k, "Ghost", 0, winreg.REG_SZ, r"C:\gone\ghost.exe")
        try:
            f = registry_cleaner._mk("regrun", "test", "HKCU", self.SUB, "64", value="Ghost")
            with mock.patch.object(registry_cleaner, "data_dir", return_value=Path(tempfile.mkdtemp())):
                res = registry_cleaner.fix_registry([f], dry_run=False)
                self.assertEqual(res.removed, 1, res.skipped)
                with self.assertRaises(FileNotFoundError):
                    winreg.QueryValueEx(winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.SUB), "Ghost")
                self.assertEqual(registry_cleaner.restore_backup(registry_cleaner.list_backups()[-1]), 1)
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.SUB) as k:
                    self.assertEqual(winreg.QueryValueEx(k, "Ghost")[0], r"C:\gone\ghost.exe")
        finally:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, self.SUB)
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\PCForgeTest")


class CleanerGuards(unittest.TestCase):
    def test_pattern_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            keep = os.path.join(d, "important.txt")
            Path(keep).write_text("x")
            f = safety.Finding("memdump", "Memory dump files", keep, 1, meta=dict(root=d, pattern="MEMORY.DMP"))
            res = cleaner.clean([f], dry_run=False)
            self.assertTrue(os.path.exists(keep))
            self.assertEqual(res.skipped[0][1], "no safe root recorded")

    def test_matching_pattern_inside_root_is_cleaned(self):
        with tempfile.TemporaryDirectory() as d:
            dump = os.path.join(d, "MEMORY.DMP")
            Path(dump).write_bytes(b"d" * 10)
            f = safety.Finding("memdump", "Memory dump files", dump, 10, meta=dict(root=d, pattern="MEMORY.DMP"))
            self.assertEqual(cleaner.clean([f], dry_run=False).freed, 10)
            self.assertFalse(os.path.exists(dump))

    def test_finding_without_root_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.txt")
            Path(p).write_text("x")
            cleaner.clean([safety.Finding("x", "x", p, 1)], dry_run=False)
            self.assertTrue(os.path.exists(p))


class IgnoreList(unittest.TestCase):
    def test_ignored_folder_hides_children(self):
        with tempfile.TemporaryDirectory() as data:
            with mock.patch.object(safety, "data_dir", return_value=Path(data)):
                safety.add_ignore(r"C:\Keep\This")
                fs = [safety.Finding("a", "a", r"C:\Keep\This\file.tmp"), safety.Finding("a", "a", r"C:\Keep\Thisother\x"),
                      safety.Finding("a", "a", r"C:\Other\y")]
                kept = [f.path for f in safety.filter_ignored(fs)]
                self.assertEqual(kept, [r"C:\Keep\Thisother\x", r"C:\Other\y"])
                safety.remove_ignore(r"C:\Keep\This")
                self.assertEqual(len(safety.filter_ignored(fs)), 3)


class StartupParsing(unittest.TestCase):
    def test_only_logon_and_boot_tasks_count(self):
        from pcforge import startup
        rows = [dict(Name="Updater", Path="\\", Exec=r"C:\x\u.exe", Args="/s", Triggers="MSFT_TaskLogonTrigger"),
                dict(Name="Nightly", Path="\\", Exec=r"C:\x\n.exe", Args="", Triggers="MSFT_TaskDailyTrigger")]
        items = startup.parse_tasks(rows)
        self.assertEqual([i.name for i in items], ["Updater"])
        self.assertTrue(items[0].recommend_disable)

    def test_windows_and_security_services_are_left_alone(self):
        from pcforge import startup
        rows = [dict(Name="Spooler", DisplayName="Print Spooler", PathName=r"C:\Windows\System32\spoolsv.exe"),
                dict(Name="AvastSvc", DisplayName="Avast Antivirus", PathName=r'"C:\Program Files\Avast\AvastSvc.exe"'),
                dict(Name="FooUpdate", DisplayName="Foo Updater Service", PathName=r'"C:\Program Files\Foo\up.exe"')]
        items = startup.parse_services(rows)
        self.assertEqual([i.name for i in items], ["Avast Antivirus", "Foo Updater Service"])
        self.assertFalse(items[0].recommend_disable, "security software must never be suggested")
        self.assertTrue(items[1].recommend_disable)


class RegistryNew(unittest.TestCase):
    def test_mui_name_parsing(self):
        m = registry_cleaner._MUI_RE.match(r"C:\Program Files\X\app.exe.FriendlyAppName")
        self.assertEqual(m.group(1), r"C:\Program Files\X\app.exe")

    def test_risky_scans_not_preselected(self):
        f = registry_cleaner._mk("regsvc", "Service with missing program", "HKLM", r"SYSTEM\X", "64", risk="medium")
        self.assertFalse(f.selected)
        self.assertTrue(registry_cleaner._mk("regfont", "f", "HKLM", "S", "64").selected)


class HistoryAndReport(unittest.TestCase):
    def setUp(self):
        # modules bind data_dir by name at import time, so point every one of them at a temp folder
        self.data = tempfile.mkdtemp()
        for mod in (safety, history, protection):
            p = mock.patch.object(mod, "data_dir", return_value=Path(self.data))
            p.start()
            self.addCleanup(p.stop)

    def test_history_groups_and_words(self):
        for _ in range(3):
            safety.log_action("delete", "C:\\x", freed=1024 * 1024)
        safety.log_action("registry-delete", "HKCU\\X")
        rows = history.recent_actions()
        texts = [r.text for r in rows]
        self.assertTrue(any("Removed 3 file(s)" in t and "3.0 MB" in t for t in texts), texts)
        self.assertTrue(any("registry entry" in t for t in texts), texts)
        self.assertTrue([r for r in rows if "registry" in r.text][0].undoable)

    def test_quarantine_restore_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            victim = Path(d, "bad.exe")
            victim.write_bytes(b"MZ")
            self.assertIsNotNone(protection.quarantine(str(victim)))
            self.assertFalse(victim.exists())
            item = history.quarantined()[0]
            victim.write_bytes(b"something new is here now")
            self.assertFalse(history.restore_quarantined(item), "must not overwrite a file that exists")
            victim.unlink()
            self.assertTrue(history.restore_quarantined(item))
            self.assertEqual(victim.read_bytes(), b"MZ")

    def test_report_text(self):
        rep = ai_mode.Report(score=82, notes=["a note"], steps=[ai_mode.Step("Remove junk", "10 items", 5, lambda dry: "x")])
        text = report.build_report(rep)
        self.assertIn("Health score: 82/100 (Good)", text)
        self.assertIn("Remove junk: 10 items", text)
        self.assertIn("a note", text)


class IconAsset(unittest.TestCase):
    def test_icon_files_are_valid(self):
        root = Path(__file__).resolve().parent.parent / "assets"
        ico = (root / "icon.ico").read_bytes()
        self.assertEqual(ico[:4], b"\x00\x00\x01\x00")
        self.assertEqual((root / "icon.png").read_bytes()[:8], b"\x89PNG\r\n\x1a\n")


class Protection(unittest.TestCase):
    def test_url_heuristics(self):
        self.assertEqual(protection.check_url("https://www.python.org/downloads", set())["verdict"], "ok")
        self.assertEqual(protection.check_url("http://paypal.secure-login.example.xyz/verify", set())["verdict"], "block")
        self.assertIn("raw IP", protection.check_url("http://192.168.1.5/login", set())["reasons"][0])
        self.assertEqual(protection.check_url("http://evil.test/x", {"evil.test"})["verdict"], "block")

    def test_file_heuristics(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "invoice.pdf.exe")
            Path(p).write_bytes(b"MZ")
            f = protection.check_file(p, set())
            self.assertIsNotNone(f)
            self.assertEqual(f.risk, "high")
            ok = os.path.join(d, "notes.txt")
            Path(ok).write_text("hello")
            self.assertIsNone(protection.check_file(ok, set()))

    def test_hash_blocklist(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "thing.exe")
            Path(p).write_bytes(b"MZ-pretend-malware")
            digest = protection.sha256(p)
            self.assertIn("blocklist", protection.check_file(p, {digest}).label)

    def test_eml_spoof(self):
        eml = ("From: \"PayPal Support\" <help@pay-pal-secure.top>\nReply-To: <collect@other.example>\n"
               "Authentication-Results: mx; spf=fail; dkim=none\nSubject: Verify\nContent-Type: text/plain\n\n"
               "Click http://192.0.2.9/login now\n")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.eml")
            Path(p).write_text(eml)
            r = protection.check_eml(p)
        self.assertEqual(r["verdict"], "dangerous")

    def test_folder_guard_canary(self):
        alerts = []
        with tempfile.TemporaryDirectory() as d:
            g = protection.FolderGuard([d], alerts.append, interval=0.2)
            g.start()
            time.sleep(0.3)
            Path(d, protection.CANARY).write_text("tampered by ransomware")
            time.sleep(0.8)
            g.stop()
        self.assertTrue(any("Canary" in a for a in alerts), alerts)


class Toolbox(unittest.TestCase):
    def test_shred_removes_file_and_dry_run_does_not(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.bin")
            Path(p).write_bytes(os.urandom(5000))
            self.assertTrue(toolbox.shred_file(p, dry_run=True))
            self.assertTrue(os.path.exists(p))
            self.assertTrue(toolbox.shred_file(p, passes=1, dry_run=False))
            self.assertEqual(os.listdir(d), [])

    def test_large_files(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "big.bin").write_bytes(b"0" * (2 * 1024 * 1024))
            Path(d, "small.bin").write_bytes(b"0")
            hits = toolbox.find_large_files([d], min_mb=1)
            self.assertEqual([os.path.basename(p) for _s, p in hits], ["big.bin"])


class Hardening(unittest.TestCase):
    def test_firefox_apply_and_revert_preserves_user_prefs(self):
        with tempfile.TemporaryDirectory() as prof, tempfile.TemporaryDirectory() as data:
            userjs = Path(prof, "user.js")
            userjs.write_text('user_pref("my.own.pref", 1);\n')
            with mock.patch.object(hardening, "firefox_profiles", return_value=[prof]), \
                    mock.patch.object(hardening, "data_dir", return_value=Path(data)):
                self.assertEqual(hardening.apply_firefox(), 1)
                self.assertIn("resistFingerprinting", userjs.read_text())
                self.assertEqual(hardening.apply_firefox(), 0, "applying twice must not duplicate")
                hardening.revert()
            self.assertEqual(userjs.read_text().strip(), 'user_pref("my.own.pref", 1);')


class Turbo(unittest.TestCase):
    def test_never_targets_self_or_protected(self):
        names = {p.name().lower() for p in turbo.candidates("game")}
        self.assertNotIn("explorer.exe", names)
        self.assertNotIn("python.exe", names)
        self.assertNotIn("svchost.exe", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
