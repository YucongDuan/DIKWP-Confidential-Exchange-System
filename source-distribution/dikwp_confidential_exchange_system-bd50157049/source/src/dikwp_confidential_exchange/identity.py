from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from .util import b64e, b64d, fingerprint_from_public, read_json, write_json


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def generate_identity(name: str, out_dir: str | Path, passphrase: str) -> dict[str, Any]:
    """Generate Ed25519 signing + X25519 exchange keys.

    Writes private.json and public.json. Private keys are encrypted with the given passphrase.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sign_private = ed25519.Ed25519PrivateKey.generate()
    exchange_private = x25519.X25519PrivateKey.generate()
    encryption = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))

    sign_priv_pem = sign_private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )
    exch_priv_pem = exchange_private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )
    sign_pub = sign_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    exch_pub = exchange_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public_doc = {
        "protocol": "DCE-1",
        "name": name,
        "created_at": _utc_now(),
        "exchange_public": b64e(exch_pub),
        "sign_public": b64e(sign_pub),
    }
    public_doc["fingerprint"] = fingerprint_from_public(public_doc)
    private_doc = {
        "protocol": "DCE-1",
        "name": name,
        "created_at": public_doc["created_at"],
        "public_fingerprint": public_doc["fingerprint"],
        "exchange_private_pem_b64": b64e(exch_priv_pem),
        "sign_private_pem_b64": b64e(sign_priv_pem),
        "public": public_doc,
    }
    write_json(out / "private.json", private_doc)
    write_json(out / "public.json", public_doc)
    return public_doc


def load_private_identity(path: str | Path, passphrase: str) -> tuple[dict[str, Any], ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey]:
    doc = read_json(path)
    sign_pem = b64d(doc["sign_private_pem_b64"])
    exch_pem = b64d(doc["exchange_private_pem_b64"])
    sign_private = serialization.load_pem_private_key(sign_pem, password=passphrase.encode("utf-8"))
    exch_private = serialization.load_pem_private_key(exch_pem, password=passphrase.encode("utf-8"))
    if not isinstance(sign_private, ed25519.Ed25519PrivateKey):
        raise TypeError("private signing key is not Ed25519")
    if not isinstance(exch_private, x25519.X25519PrivateKey):
        raise TypeError("private exchange key is not X25519")
    return doc, sign_private, exch_private


def load_public_identity(path: str | Path) -> dict[str, Any]:
    doc = read_json(path)
    expected = fingerprint_from_public(doc)
    if doc.get("fingerprint") != expected:
        raise ValueError("public identity fingerprint mismatch; file may be corrupted")
    return doc


def public_x25519(doc: dict[str, Any]) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(b64d(doc["exchange_public"]))


def public_ed25519(doc: dict[str, Any]) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(b64d(doc["sign_public"]))
