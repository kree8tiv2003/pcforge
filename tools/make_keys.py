"""Create the signing key pair for updates. Run once.

  python tools/make_keys.py "C:\\Users\\you\\PCForge-keys"

The PRIVATE key file stays on your PC (back it up somewhere safe, never share it, never put it in the
project folder). The PUBLIC key is printed; paste it into pcforge/brand.py as UPDATE_PUBLIC_KEY.
If you lose the private key, already-installed copies can't be updated automatically any more.
"""
import base64
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.expanduser("~"), "PCForge-keys")
os.makedirs(out, exist_ok=True)
path = os.path.join(out, "update_private.key")
if os.path.exists(path):
    sys.exit(f"{path} already exists; refusing to overwrite your signing key.")
key = Ed25519PrivateKey.generate()
raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
with open(path, "wb") as fh:
    fh.write(base64.b64encode(raw))
pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print("private key written to:", path)
print("UPDATE_PUBLIC_KEY =", base64.b64encode(pub).decode())
