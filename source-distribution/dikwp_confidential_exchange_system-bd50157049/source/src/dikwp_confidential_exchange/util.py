from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Return deterministic JSON bytes used for signatures and hashes."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, obj: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def fingerprint_from_public(public_doc: dict[str, Any]) -> str:
    """Stable public identity fingerprint."""
    core = {
        "name": public_doc.get("name"),
        "exchange_public": public_doc.get("exchange_public"),
        "sign_public": public_doc.get("sign_public"),
        "protocol": public_doc.get("protocol", "DCE-1"),
    }
    digest = sha256_hex(canonical_json(core))
    return ":".join(digest[i:i+4] for i in range(0, 32, 4))
