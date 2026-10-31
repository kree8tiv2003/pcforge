import base64
import hashlib
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["LOCALAPPDATA"] = tempfile.mkdtemp(prefix="pcforge-test-")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from pcforge import settings, updater  # noqa: E402


def keypair():
    k = Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return k, base64.b64encode(pub).decode()


def signed_manifest(key, version, exe_bytes, url):
    m = {"version": version, "url": url, "sha256": hashlib.sha256(exe_bytes).hexdigest(), "size": len(exe_bytes), "notes": "n"}
    m["signature"] = base64.b64encode(key.sign(updater.signed_payload(m))).decode()
    return m


class Server:
    """Tiny local web server standing in for the update host. `files` may be filled in after start."""

    def __init__(self, files: dict):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = files.get(self.path)
                self.send_response(200 if body is not None else 404)
                self.end_headers()
                if body is not None:
                    self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class Versions(unittest.TestCase):
    def test_compare(self):
        self.assertTrue(updater.is_newer("0.2.0", "0.1.0"))
        self.assertTrue(updater.is_newer("0.10.0", "0.9.9"))
        self.assertTrue(updater.is_newer("1.0", "0.9.9"))
        self.assertFalse(updater.is_newer("0.1.0", "0.1.0"))
        self.assertFalse(updater.is_newer("0.1", "0.1.0"))
        with self.assertRaises(updater.UpdateError):
            updater.parse_version("nonsense")


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.key, self.pub = keypair()
        self.exe = os.urandom(200_000)
        self.files: dict = {}
        self.srv = Server(self.files)
        self.addCleanup(self.srv.close)
        self.url = self.srv.base + "/latest.json"

    def publish(self, manifest, exe=None):
        self.files["/latest.json"] = json.dumps(manifest).encode()
        self.files["/PCForge.exe"] = self.exe if exe is None else exe

    def check(self, current="0.1.0"):
        return updater.check(self.url, current=current, public_key=self.pub, allow_loopback=True)

    def test_full_cycle(self):
        self.publish(signed_manifest(self.key, "9.0.0", self.exe, self.srv.base + "/PCForge.exe"))
        info = self.check()
        self.assertEqual(info.version, "9.0.0")
        with tempfile.TemporaryDirectory() as d:
            path = updater.download(info, dest_dir=Path(d), allow_loopback=True)
            self.assertEqual(path.read_bytes(), self.exe)

    def test_up_to_date_returns_none(self):
        self.publish(signed_manifest(self.key, "0.1.0", self.exe, self.srv.base + "/PCForge.exe"))
        self.assertIsNone(self.check())

    def test_wrong_key_signature_is_rejected(self):
        other, _ = keypair()
        self.publish(signed_manifest(other, "9.0.0", self.exe, self.srv.base + "/PCForge.exe"))
        with self.assertRaises(updater.UpdateError) as cm:
            self.check()
        self.assertIn("signature", str(cm.exception))

    def test_tampered_manifest_is_rejected(self):
        m = signed_manifest(self.key, "9.0.0", self.exe, self.srv.base + "/PCForge.exe")
        m["url"] = "https://evil.example/PCForge.exe"            # attacker swaps the download address
        self.publish(m)
        with self.assertRaises(updater.UpdateError):
            self.check()

    def test_download_that_differs_from_signed_hash_is_discarded(self):
        self.publish(signed_manifest(self.key, "9.0.0", self.exe, self.srv.base + "/PCForge.exe"),
                     exe=os.urandom(len(self.exe)))              # same size, different bytes
        info = self.check()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(updater.UpdateError):
                updater.download(info, dest_dir=Path(d), allow_loopback=True)
            self.assertEqual(list(Path(d).iterdir()), [], "a bad download must not be left behind")

    def test_oversized_download_is_stopped(self):
        self.publish(signed_manifest(self.key, "9.0.0", self.exe, self.srv.base + "/PCForge.exe"), exe=self.exe + b"x" * 5000)
        info = self.check()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(updater.UpdateError):
                updater.download(info, dest_dir=Path(d), allow_loopback=True)

    def test_no_key_configured_fails_closed(self):
        with self.assertRaises(updater.UpdateError):
            updater.verify_signature({"version": "1", "sha256": "0" * 64, "size": 1, "url": "x", "signature": "AA=="}, "")

    def test_plain_http_to_the_internet_is_refused(self):
        with self.assertRaises(updater.UpdateError):
            updater.check("http://example.com/latest.json", current="0.1.0", public_key=self.pub)

    def test_no_server_configured(self):
        with self.assertRaises(updater.UpdateError):
            updater.check("", current="0.1.0", public_key=self.pub)


@unittest.skipUnless(os.name == "nt", "Windows only")
class SwapScript(unittest.TestCase):
    def run_script(self, lock_target=False):
        d = Path(tempfile.mkdtemp())
        target, new, log = d / "PCForge.exe", d / "new.exe", d / "result.txt"
        target.write_bytes(b"OLD")
        new.write_bytes(b"NEW")
        gone = subprocess.Popen([sys.executable, "-c", "pass"])
        gone.wait()                                              # a process id that has already finished
        script = d / "swap.cmd"
        script.write_text(updater.build_swap_script(gone.pid, new, target, log, relaunch=False, swap_tries=2), encoding="utf-8")
        fh = open(target, "r+b") if lock_target else None        # an open handle makes Windows refuse the rename
        try:
            subprocess.run(["cmd", "/c", str(script)], timeout=120, capture_output=True)
        finally:
            if fh:
                fh.close()
        return d, target, new, log

    def test_swap_replaces_exe_and_keeps_backup(self):
        d, target, new, log = self.run_script()
        self.assertEqual(target.read_bytes(), b"NEW")
        self.assertEqual(Path(str(target) + ".old").read_bytes(), b"OLD")
        self.assertEqual(log.read_text().strip(), "ok")
        self.assertFalse((d / "swap.cmd").exists(), "the script deletes itself")

    def test_failed_swap_leaves_old_exe_in_place(self):
        d, target, new, log = self.run_script(lock_target=True)
        self.assertEqual(log.read_text().strip(), "failed")
        self.assertEqual(target.read_bytes(), b"OLD", "the working version must survive a failed update")
        self.assertTrue(new.exists(), "the downloaded file is kept for a retry")


class Settings(unittest.TestCase):
    def test_defaults_and_roundtrip(self):
        self.assertTrue(settings.get("auto_check"))
        self.assertFalse(settings.get("auto_download"))
        settings.set_("auto_download", True)
        self.assertTrue(settings.get("auto_download"))
        settings.set_("auto_download", False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
