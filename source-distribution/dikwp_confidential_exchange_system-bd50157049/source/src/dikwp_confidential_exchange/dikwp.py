from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any

import yaml

from .util import read_json, write_json, sha256_hex, canonical_json

LANES = ["D", "I", "K", "W", "P"]
CLASSIFICATIONS = {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET", "TOP_SECRET"}
MODES = {"memo", "zdc"}
CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,64}$")


class ValidationError(ValueError):
    pass


def load_yaml_or_json(path: str | Path) -> Any:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        import json
        return json.loads(text)
    return yaml.safe_load(text)


def load_codebook(path: str | Path) -> dict[str, Any]:
    return load_yaml_or_json(path)


def _parse_time(value: str, field: str) -> None:
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt.datetime.fromisoformat(value)
    except Exception as exc:
        raise ValidationError(f"{field} must be ISO-8601 datetime") from exc


def validate_payload(payload: dict[str, Any], codebook: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("payload must be an object")
    required = ["dikwp_version", "mode", "purpose", "classification", "expires_at", "lanes"]
    for key in required:
        if key not in payload:
            raise ValidationError(f"missing required field: {key}")
    if payload["dikwp_version"] != "DCE-DIKWP-1":
        raise ValidationError("unsupported dikwp_version")
    if payload["mode"] not in MODES:
        raise ValidationError("mode must be memo or zdc")
    if payload["classification"] not in CLASSIFICATIONS:
        raise ValidationError("invalid classification")
    _parse_time(payload["expires_at"], "expires_at")
    lanes = payload["lanes"]
    if not isinstance(lanes, dict):
        raise ValidationError("lanes must be an object")
    if set(lanes.keys()) != set(LANES):
        raise ValidationError("lanes must contain exactly D, I, K, W, P")

    if payload["mode"] == "zdc":
        if codebook is None:
            raise ValidationError("zdc mode requires a codebook")
        allowed = codebook.get("lanes", {})
        for lane in LANES:
            items = lanes.get(lane)
            if not isinstance(items, list):
                raise ValidationError(f"lane {lane} must be a list in zdc mode")
            for item in items:
                if not isinstance(item, dict):
                    raise ValidationError(f"lane {lane} item must be an object")
                if set(item.keys()) - {"code", "score", "ref", "note_code"}:
                    raise ValidationError(f"lane {lane} has fields not permitted in zdc mode")
                code = item.get("code")
                if not isinstance(code, str) or not CODE_RE.match(code):
                    raise ValidationError(f"lane {lane} item code is invalid")
                if code not in allowed.get(lane, {}):
                    raise ValidationError(f"lane {lane} code {code} not in codebook")
                if "score" in item and item["score"] not in [0, 1, 2, 3, 4, 5]:
                    raise ValidationError(f"lane {lane} score must be integer 0..5")
                if "ref" in item and not isinstance(item["ref"], str):
                    raise ValidationError(f"lane {lane} ref must be a string")
                if "note_code" in item and item["note_code"] not in codebook.get("note_codes", {}):
                    raise ValidationError(f"lane {lane} note_code not in codebook")
    else:
        # Memo mode permits free text, but still fences it inside DIKWP lanes.
        for lane in LANES:
            if not isinstance(lanes.get(lane), str):
                raise ValidationError(f"lane {lane} must be a string in memo mode")
        for key in payload.keys():
            if key not in required + ["title", "evidence_refs", "constraints"]:
                raise ValidationError(f"undeclared top-level field not allowed: {key}")

    return payload


def compile_payload(in_path: str | Path, out_path: str | Path, codebook_path: str | Path | None = None) -> dict[str, Any]:
    payload = load_yaml_or_json(in_path)
    codebook = load_codebook(codebook_path) if codebook_path else None
    payload = validate_payload(payload, codebook)
    payload["payload_hash_sha256"] = sha256_hex(canonical_json({k: v for k, v in payload.items() if k != "payload_hash_sha256"}))
    write_json(out_path, payload)
    return payload
