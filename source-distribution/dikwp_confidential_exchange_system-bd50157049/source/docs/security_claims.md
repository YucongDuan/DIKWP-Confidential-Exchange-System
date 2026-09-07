# Security Claims and Limits

## Claim C1 - Confidentiality

If recipient private keys remain secret and the cryptographic assumptions hold, a passive or active network attacker cannot read sealed payloads.

## Claim C2 - Integrity and authenticity

If sender signing keys remain secret and fingerprints are verified out-of-band, a receiver can detect tampering and sender impersonation.

## Claim C3 - Payload representation channel reduction

In ZDC mode, the compiler rejects free text and unregistered fields. Payloads are canonical JSON, and plaintext frames are fixed-size with zero padding. This removes undeclared representation channels at the trusted compiler boundary.

## Claim C4 - Hash-only auditability

An auditor can verify that a message existed, had a declared purpose, and matched a payload hash without seeing plaintext.

## Non-claim N1 - No absolute secrecy against endpoint compromise

DCE cannot protect against malware, screen capture, memory compromise, recipient disclosure, coercion, or a malicious user deliberately encoding secrets in timing or allowed semantic choices.

## Non-claim N2 - No home-made post-quantum cryptography

The package exposes a PQC migration slot. Production systems should bind to validated ML-KEM/ML-DSA implementations.
