import os
import base64
import json
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_KEY_ENV = "PICKAXE_LOCAL_KEY"

def _b64decode(s: str) -> bytes:
    # URL-safe base64, tolerate missing padding
    s = s.strip()
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)

def load_local_key(env_name: str = DEFAULT_KEY_ENV) -> bytes:
    """Load 32-byte AES key from environment variable.

    Accepts:
    - URL-safe base64 (recommended): 32 bytes after decode
    - hex string (64 hex chars)
    """
    val = os.getenv(env_name, "").strip()
    if not val:
        raise RuntimeError(
            f"Missing local encryption key. Set env var {env_name} to a 32-byte key (base64 or hex)."
        )
    # hex
    if all(c in "0123456789abcdefABCDEF" for c in val) and len(val) == 64:
        key = bytes.fromhex(val)
    else:
        key = _b64decode(val)
    if len(key) != 32:
        raise RuntimeError(f"{env_name} must decode to 32 bytes for AES-256-GCM. Got {len(key)} bytes.")
    return key

def encrypt_json(obj: Any, *, key: bytes) -> Dict[str, str]:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    pt = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    ct = aes.encrypt(nonce, pt, None)
    return {
        "v": 1,
        "alg": "AES-256-GCM",
        "nonce_b64": base64.urlsafe_b64encode(nonce).decode("utf-8").rstrip("="),
        "ciphertext_b64": base64.urlsafe_b64encode(ct).decode("utf-8").rstrip("="),
    }

def decrypt_json(payload: Dict[str, str], *, key: bytes) -> Any:
    if not isinstance(payload, dict):
        raise RuntimeError("Invalid encrypted payload")
    if payload.get("v") != 1:
        raise RuntimeError("Unsupported encrypted payload version")
    if payload.get("alg") != "AES-256-GCM":
        raise RuntimeError("Unsupported encryption algorithm")
    nonce = _b64decode(payload["nonce_b64"])
    ct = _b64decode(payload["ciphertext_b64"])
    aes = AESGCM(key)
    pt = aes.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))
