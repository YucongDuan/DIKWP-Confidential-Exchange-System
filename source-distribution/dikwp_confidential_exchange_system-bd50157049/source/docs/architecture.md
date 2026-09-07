# Architecture

## 1. Semantic plane

The sender compiles a message into D/I/K/W/P lanes.

- D: evidence and factual substrate.
- I: distinctions, boundaries, and differences.
- K: integrated conclusions.
- W: value constraints and tradeoffs.
- P: requested movement from input state to output state.

## 2. Disclosure plane

Two modes exist:

- ZDC mode: finite codebook; no arbitrary strings except bounded references.
- Memo mode: free text in five lanes; confidentiality strong, dark-channel control weaker.

## 3. Cryptographic plane

- Ed25519 identities sign the envelope.
- X25519 ephemeral-static agreement produces a shared secret.
- HKDF-SHA256 derives the envelope key.
- ChaCha20-Poly1305 encrypts and authenticates a fixed-size frame.
- Zero padding is checked after decryption.

## 4. Audit plane

The audit record contains hashes and declared control claims only. It does not expose plaintext.

## 5. PQC extension plane

The code exposes a protocol slot for hybrid ML-KEM and ML-DSA integration.
Production use should employ validated post-quantum providers rather than ad hoc implementations.
