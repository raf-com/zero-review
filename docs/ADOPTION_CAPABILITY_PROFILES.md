# Adoption capability profiles

Repositories enroll against an explicit capability profile. A profile describes
what can be proven; it does not imply that the repository is ready.

| Profile | Required local capabilities | Required external receipts | Allowed outcome |
|---|---|---|---|
| `observe` | workflow syntax, bounded collector, local receipt retention | none | advisory findings only |
| `pilot` | `observe` plus packet validation, replay/contradiction tests, rollback owner | hosted run on exact head, retention confirmation, protection readback | one-repository pilot |
| `required` | `pilot` plus protected evaluator SHA, signed manifest, supply-chain check | independent approval, attestation verification, required-check readback | merge gate |
| `apex-advisory` | `required` plus event schema and idempotent producer | authenticated producer, trusted sink, signed round-trip and witness | advisory Apex events |

Enrollment must record repository, profile, exact evaluator SHA, adapter set,
owner, retention policy, and expiry. Missing evidence yields `blocked` or
`not_proven`; it never upgrades a profile automatically.
