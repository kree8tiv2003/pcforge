"""Make the signed update description (latest.json) for a new PCForge.exe.

  python tools/publish_update.py --exe dist/PCForge.exe --version 0.2.0 ^
      --url https://example.com/PCForge.exe --key C:\\Users\\you\\PCForge-keys\\update_private.key ^
      --notes "What changed"

Upload BOTH files (PCForge.exe and latest.json) to the address you configured as UPDATE_MANIFEST_URL.
The version number must match brand.VERSION inside that exe, or installed copies will keep offering the update.
"""
import argparse
import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pcforge.updater import signed_payload  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--exe", required=True)
ap.add_argument("--version", required=True)
ap.add_argument("--url", required=True)
ap.add_argument("--key", required=True)
ap.add_argument("--notes", default="")
ap.add_argument("--out", default=None)
a = ap.parse_args()

data = open(a.exe, "rb").read()
manifest = {"version": a.version, "url": a.url, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "notes": a.notes}
key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(open(a.key, "rb").read()))
manifest["signature"] = base64.b64encode(key.sign(signed_payload(manifest))).decode()
out = a.out or os.path.join(os.path.dirname(os.path.abspath(a.exe)), "latest.json")
with open(out, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=1)
print("wrote", out)
print(json.dumps({k: v for k, v in manifest.items() if k != "signature"}, indent=1))
