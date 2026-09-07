from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
required = [
    "README.md",
    "codebooks/dikwp_secure_exchange_v1.yaml",
    "policies/classification_policy.yaml",
    "docs/threat_model.md",
    "docs/security_claims.md",
    "src/dikwp_confidential_exchange/crypto.py",
    "tests/test_dce.py",
]
print("DCE hardening check")
ok = True
for r in required:
    exists = (ROOT / r).exists()
    print(f"[{ 'OK' if exists else 'MISS' }] {r}")
    ok = ok and exists
print("status:", "PASS" if ok else "FAIL")
raise SystemExit(0 if ok else 2)
