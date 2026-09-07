# Operations Manual

## Ceremony 1: Identity setup

1. Generate identities on clean machines.
2. Print and verbally verify public fingerprints out-of-band.
3. Store private keys in encrypted storage or hardware-backed vaults.
4. Rotate keys after incidents, role changes, or fixed time windows.

## Ceremony 2: ZDC confidential exchange

1. Author chooses a purpose and classification.
2. Author maps content to DIKWP codebook entries.
3. Compiler validates payload and rejects free text.
4. Sender encrypts to recipient.
5. Recipient verifies sender fingerprint before decryption.
6. Auditor receives hash-only audit record if required.

## Ceremony 3: Free memo exchange

Use only when expressive content is necessary. The memo is still encrypted and signed, but it is not zero-dark-channel.

## Emergency freeze

If a bundle fails verification, padding check, fingerprint check, or purpose binding:

1. Do not decrypt further copies.
2. Quarantine the bundle.
3. Export audit hash.
4. Rotate keys if private key compromise is plausible.
