from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .identity import load_private_identity, load_public_identity, public_ed25519, public_x25519
from .util import b64e, b64d, canonical_json, sha256_hex, write_json, read_json

MAGIC = b"DCE1"
FRAME_HEADER_LEN = 12
DEFAULT_FIXED_SIZE = 16384


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _frame(payload: bytes, fixed_size: int) -> bytes:
    if fixed_size < FRAME_HEADER_LEN + len(payload):
        raise ValueError(f"payload too large for fixed_size={fixed_size}")
    return MAGIC + len(payload).to_bytes(8, "big") + payload + b"\x00" * (fixed_size - FRAME_HEADER_LEN - len(payload))


def _unframe(frame: bytes) -> bytes:
    if len(frame) < FRAME_HEADER_LEN or frame[:4] != MAGIC:
        raise ValueError("invalid DCE frame")
    n = int.from_bytes(frame[4:12], "big")
    if n > len(frame) - FRAME_HEADER_LEN:
        raise ValueError("invalid DCE frame length")
    if any(frame[FRAME_HEADER_LEN + n:]):
        raise ValueError("non-zero padding rejected; possible covert-channel or corruption")
    return frame[FRAME_HEADER_LEN:FRAME_HEADER_LEN + n]


def _derive_key(shared: bytes, salt: bytes, aad_context: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"DIKWP-DCE-v1 envelope key" + aad_context,
    ).derive(shared)


def encrypt_file(
    sender_private_path: str | Path,
    sender_passphrase: str,
    recipient_public_path: str | Path,
    payload_path: str | Path,
    out_path: str | Path,
    purpose: str,
    fixed_size: int = DEFAULT_FIXED_SIZE,
    strict_constant_size: bool = True,
) -> dict[str, Any]:
    sender_doc, sender_sign, _sender_exchange = load_private_identity(sender_private_path, sender_passphrase)
    recipient_doc = load_public_identity(recipient_public_path)
    payload = Path(payload_path).read_bytes()
    frame = _frame(payload, fixed_size if strict_constant_size else FRAME_HEADER_LEN + len(payload))

    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_raw = eph_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = eph_priv.exchange(public_x25519(recipient_doc))

    header = {
        "protocol": "DCE-1",
        "created_at": _utc_now(),
        "purpose": purpose,
        "sender_fingerprint": sender_doc["public"]["fingerprint"],
        "recipient_fingerprint": recipient_doc["fingerprint"],
        "cipher": "X25519-HKDF-SHA256-ChaCha20Poly1305-Ed25519",
        "pqc_profile": "PQC-ready interface: prefer ML-KEM/ML-DSA provider for production hybrid mode",
        "constant_size": strict_constant_size,
        "fixed_plaintext_frame_size": len(frame),
        "payload_sha256": sha256_hex(payload),
        "ephemeral_exchange_public": b64e(eph_pub_raw),
    }
    aad = canonical_json(header)
    salt = sha256_hex(eph_pub_raw + recipient_doc["fingerprint"].encode() + sender_doc["public"]["fingerprint"].encode()).encode()
    key = _derive_key(shared, salt, aad)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, frame, aad)
    to_sign = canonical_json({"header": header, "nonce": b64e(nonce), "ciphertext_sha256": sha256_hex(ciphertext)})
    signature = sender_sign.sign(to_sign)
    bundle = {
        "header": header,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "sender_signature": b64e(signature),
    }
    write_json(out_path, bundle)
    return bundle


def verify_bundle(bundle_path: str | Path, sender_public_path: str | Path) -> dict[str, Any]:
    bundle = read_json(bundle_path)
    sender_doc = load_public_identity(sender_public_path)
    if bundle["header"]["sender_fingerprint"] != sender_doc["fingerprint"]:
        raise ValueError("sender fingerprint mismatch")
    ciphertext = b64d(bundle["ciphertext"])
    to_verify = canonical_json({
        "header": bundle["header"],
        "nonce": bundle["nonce"],
        "ciphertext_sha256": sha256_hex(ciphertext),
    })
    public_ed25519(sender_doc).verify(b64d(bundle["sender_signature"]), to_verify)
    return {"ok": True, "header": bundle["header"], "ciphertext_sha256": sha256_hex(ciphertext)}


def decrypt_file(
    recipient_private_path: str | Path,
    recipient_passphrase: str,
    sender_public_path: str | Path,
    bundle_path: str | Path,
    out_path: str | Path,
) -> bytes:
    verify_bundle(bundle_path, sender_public_path)
    recipient_doc, _recipient_sign, recipient_exchange = load_private_identity(recipient_private_path, recipient_passphrase)
    bundle = read_json(bundle_path)
    if bundle["header"]["recipient_fingerprint"] != recipient_doc["public"]["fingerprint"]:
        raise ValueError("recipient fingerprint mismatch")
    eph_pub = x25519.X25519PublicKey.from_public_bytes(b64d(bundle["header"]["ephemeral_exchange_public"]))
    shared = recipient_exchange.exchange(eph_pub)
    aad = canonical_json(bundle["header"])
    salt = sha256_hex(b64d(bundle["header"]["ephemeral_exchange_public"]) + recipient_doc["public"]["fingerprint"].encode() + bundle["header"]["sender_fingerprint"].encode()).encode()
    key = _derive_key(shared, salt, aad)
    frame = ChaCha20Poly1305(key).decrypt(b64d(bundle["nonce"]), b64d(bundle["ciphertext"]), aad)
    payload = _unframe(frame)
    if sha256_hex(payload) != bundle["header"]["payload_sha256"]:
        raise ValueError("payload hash mismatch")
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_bytes(payload)
    return payload
