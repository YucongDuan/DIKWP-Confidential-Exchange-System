from pathlib import Path
import json
import pytest

from dikwp_confidential_exchange.identity import generate_identity
from dikwp_confidential_exchange.dikwp import compile_payload, ValidationError
from dikwp_confidential_exchange.crypto import encrypt_file, decrypt_file, verify_bundle
from dikwp_confidential_exchange.audit import make_audit_record

ROOT = Path(__file__).resolve().parents[1]


def test_roundtrip_zdc(tmp_path):
    generate_identity("Alice", tmp_path / "alice", "alice-pass")
    generate_identity("Bob", tmp_path / "bob", "bob-pass")
    compiled = tmp_path / "compiled.json"
    compile_payload(ROOT / "examples/zdc_message.yaml", compiled, ROOT / "codebooks/dikwp_secure_exchange_v1.yaml")
    bundle = tmp_path / "msg.json"
    encrypt_file(tmp_path / "alice/private.json", "alice-pass", tmp_path / "bob/public.json", compiled, bundle, "TEST", fixed_size=8192)
    assert verify_bundle(bundle, tmp_path / "alice/public.json")["ok"]
    out = tmp_path / "out.json"
    decrypt_file(tmp_path / "bob/private.json", "bob-pass", tmp_path / "alice/public.json", bundle, out)
    assert json.loads(out.read_text()) == json.loads(compiled.read_text())


def test_tamper_signature_fails(tmp_path):
    generate_identity("Alice", tmp_path / "alice", "alice-pass")
    generate_identity("Bob", tmp_path / "bob", "bob-pass")
    compiled = tmp_path / "compiled.json"
    compile_payload(ROOT / "examples/zdc_message.yaml", compiled, ROOT / "codebooks/dikwp_secure_exchange_v1.yaml")
    bundle = tmp_path / "msg.json"
    encrypt_file(tmp_path / "alice/private.json", "alice-pass", tmp_path / "bob/public.json", compiled, bundle, "TEST", fixed_size=8192)
    obj = json.loads(bundle.read_text())
    obj["header"]["purpose"] = "EVIL"
    bundle.write_text(json.dumps(obj))
    with pytest.raises(Exception):
        verify_bundle(bundle, tmp_path / "alice/public.json")


def test_zdc_rejects_free_text(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text('''
dikwp_version: DCE-DIKWP-1
mode: zdc
purpose: TEST
classification: SECRET
expires_at: "2026-12-31T23:59:59Z"
lanes:
  D: "free text not allowed"
  I: []
  K: []
  W: []
  P: []
''')
    with pytest.raises(ValidationError):
        compile_payload(bad, tmp_path / "out.json", ROOT / "codebooks/dikwp_secure_exchange_v1.yaml")


def test_constant_ciphertext_size(tmp_path):
    generate_identity("Alice", tmp_path / "alice", "alice-pass")
    generate_identity("Bob", tmp_path / "bob", "bob-pass")
    c1 = tmp_path / "c1.json"; c2 = tmp_path / "c2.json"
    compile_payload(ROOT / "examples/zdc_message.yaml", c1, ROOT / "codebooks/dikwp_secure_exchange_v1.yaml")
    compile_payload(ROOT / "examples/memo_message.yaml", c2)
    b1 = tmp_path / "b1.json"; b2 = tmp_path / "b2.json"
    encrypt_file(tmp_path / "alice/private.json", "alice-pass", tmp_path / "bob/public.json", c1, b1, "TEST", fixed_size=8192)
    encrypt_file(tmp_path / "alice/private.json", "alice-pass", tmp_path / "bob/public.json", c2, b2, "TEST", fixed_size=8192)
    o1 = json.loads(b1.read_text()); o2 = json.loads(b2.read_text())
    assert o1["header"]["fixed_plaintext_frame_size"] == o2["header"]["fixed_plaintext_frame_size"] == 8192
    assert len(o1["ciphertext"]) == len(o2["ciphertext"])


def test_audit_record(tmp_path):
    generate_identity("Alice", tmp_path / "alice", "alice-pass")
    generate_identity("Bob", tmp_path / "bob", "bob-pass")
    compiled = tmp_path / "compiled.json"
    compile_payload(ROOT / "examples/zdc_message.yaml", compiled, ROOT / "codebooks/dikwp_secure_exchange_v1.yaml")
    bundle = tmp_path / "msg.json"
    encrypt_file(tmp_path / "alice/private.json", "alice-pass", tmp_path / "bob/public.json", compiled, bundle, "TEST", fixed_size=8192)
    rec = make_audit_record(bundle, tmp_path / "audit.json", "test")
    assert "audit_record_sha256" in rec
    assert rec["purpose"] == "TEST"
