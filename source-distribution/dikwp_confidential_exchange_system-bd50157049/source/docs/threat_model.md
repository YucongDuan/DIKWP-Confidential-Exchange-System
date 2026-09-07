# Threat Model

## Protects against

- Passive network observers.
- Active tampering with sealed message bundles.
- Accidental over-sharing by forcing DIKWP lanes and codebook disclosure.
- Unauthorized sender impersonation if public fingerprints are verified out-of-band.
- Hash-audited governance review without plaintext exposure.

## Partially mitigates

- Metadata leakage through fixed-size encrypted frames.
- Semantic leakage by using ZDC finite codebooks instead of free text.
- Supply-chain ambiguity by binding signatures, hashes, identities, and audit records.

## Does not solve by itself

- Compromised endpoints.
- Coerced users.
- Timing, volume, or existence of communication.
- Malicious users encoding secrets in allowed semantic choices.
- Legal/process risks outside the cryptographic system.
- All future quantum threats unless PQC provider is added.

## High-assurance interpretation

DCE is not a magical secrecy oracle. Its core value is to turn secrecy into a governed interface:
what is disclosed is declared as DIKWP structure, sealed to the recipient, signed by the sender,
and recorded by hash-only audit artifacts.
