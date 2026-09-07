# DIKWP Confidential Exchange System (DCE)

DCE is a local-first, high-assurance confidential communication system.
It combines:

1. **Cryptographic confidentiality** - X25519 key agreement, HKDF-SHA256, ChaCha20-Poly1305, Ed25519 signatures.
2. **DIKWP semantic minimization** - each message is forced into D/I/K/W/P lanes.
3. **Zero-dark-channel controlled disclosure mode** - finite codebook, canonical payloads, fixed-size sealed frames, zero padding verification.
4. **Audit without plaintext disclosure** - hash-only records for governance review.
5. **PQC-ready interface** - production deployments should add ML-KEM and ML-DSA providers when certified libraries are available.

## Security truth

No software can absolutely eliminate all covert channels against a malicious endpoint:
message timing, message existence, recipient choice, free semantic content, local compromise,
and cryptographic randomness can carry information. DCE therefore gives a scoped guarantee:
inside the **trusted compiler + sealed envelope boundary**, undeclared payload representation channels are removed in ZDC mode.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .

dce init --name Alice --out identities/alice --passphrase alice-pass
dce init --name Bob --out identities/bob --passphrase bob-pass

dce compile --in examples/zdc_message.yaml --codebook codebooks/dikwp_secure_exchange_v1.yaml --out artifacts/demo/compiled.json

dce encrypt --sender-private identities/alice/private.json --sender-passphrase alice-pass \
  --recipient-public identities/bob/public.json \
  --payload artifacts/demo/compiled.json \
  --purpose HIGH_RISK_AI_GOVERNANCE_REVIEW \
  --out artifacts/demo/message.dce.json

dce verify --bundle artifacts/demo/message.dce.json --sender-public identities/alice/public.json

dce decrypt --recipient-private identities/bob/private.json --recipient-passphrase bob-pass \
  --sender-public identities/alice/public.json \
  --bundle artifacts/demo/message.dce.json \
  --out artifacts/demo/decrypted.json

dce audit --bundle artifacts/demo/message.dce.json --out artifacts/demo/audit.json --operator demo
```

## Modes

- `zdc`: finite codebook only; strongest semantic leakage control.
- `memo`: DIKWP-lane free text; encrypted and authenticated, but not zero-dark-channel.

## Production hardening

Use hardware-backed keys, SSO/OIDC, endpoint hardening, tamper-evident logs, external HSM/KMS,
formal policy checks, PQC hybrid KEM/signatures, and traffic-analysis protections.
