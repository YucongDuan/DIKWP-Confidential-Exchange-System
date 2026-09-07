from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from .util import read_json, write_json, canonical_json, sha256_hex


def make_audit_record(bundle_path: str | Path, out_path: str | Path, operator: str = "local") -> dict[str, Any]:
    bundle = read_json(bundle_path)
    header = bundle["header"]
    record = {
        "audit_protocol": "DCE-AUDIT-1",
        "created_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "operator": operator,
        "sender_fingerprint": header.get("sender_fingerprint"),
        "recipient_fingerprint": header.get("recipient_fingerprint"),
        "purpose": header.get("purpose"),
        "payload_sha256": header.get("payload_sha256"),
        "ciphertext_sha256": sha256_hex(bundle["ciphertext"].encode("utf-8")),
        "header_sha256": sha256_hex(canonical_json(header)),
        "control_claims": [
            "canonical DIKWP payload recommended",
            "authenticated sender",
            "fixed-size encrypted frame if constant_size=true",
            "no plaintext payload metadata beyond header",
            "padding bytes verified as zero after decryption",
        ],
    }
    record["audit_record_sha256"] = sha256_hex(canonical_json(record))
    write_json(out_path, record)
    return record
