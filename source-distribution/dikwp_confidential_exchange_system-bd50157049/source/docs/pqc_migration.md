# Post-Quantum Migration Plan

Current local demo mode uses X25519 and Ed25519 because those algorithms are available in common Python cryptographic libraries.
Production high-value systems should migrate to a hybrid profile:

1. Add ML-KEM-768 or ML-KEM-1024 for key establishment.
2. Combine classical and PQC shared secrets with a transcript-bound KDF.
3. Add ML-DSA or SLH-DSA signatures for quantum-resistant authentication.
4. Keep classical signatures during transition for interoperability.
5. Record algorithm suite and provider validation evidence in every envelope header.

Do not implement ML-KEM or ML-DSA by hand for production. Use validated providers and keep algorithm agility.
