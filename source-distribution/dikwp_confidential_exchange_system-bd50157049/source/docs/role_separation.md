# Role Separation

| Role | Allowed action | Forbidden action |
|---|---|---|
| Author | Draft DIKWP payload | Bypass compiler |
| Compiler | Validate schema/codebook | Read or rewrite policy outside approved profile |
| Sender | Encrypt/sign bundle | Modify compiled payload after approval |
| Recipient | Verify/decrypt | Accept unverified fingerprints |
| Auditor | Review hash-only records | Demand plaintext unless policy permits |
| Governance owner | Approve codebooks and rotations | Secretly add new codes without review |

The strongest mode is two-person control: one person authors, another compiles/verifies, and a third receives hash-only audit records.
