# Migrating to zero-review 0.2

Version 0.2 intentionally fails closed on v1 review packets and overrides. The v1
schemas remain published for decoding archived evidence, but they cannot represent
the identity, typed status, release binding, nonce, or signature fields required by
the current trust contract.

Review-packet producers must now emit `zero-review.review-packet.v3`, including one
`zero-review.evidence.v2` result for each required control. Evidence v2 records the exact
argument-vector command, executable SHA-256 digest, exit code, and start/end timestamps
alongside the artifact identity and status. These fields remain producer claims until
verified against a trusted execution receipt and signed packet manifest. V1 and v2 packets remain decodable as archived
evidence but cannot pass current validation. Override producers continue to emit
`zero-review.override.v2` and bind the repository, pull-request number, base and head
SHA, release digest, nonce, signing algorithm, key ID, and signature.

`ledger-append`, `ledger-verify --strict-evidence`, `apex-event`, and
`apex-signing-payload` now require an explicit evidence-store root. Adapter execution
uses `--registry` and `--adapter-id`; direct executable selection is no longer a CLI
operation.

Authenticated Apex events now identify themselves as `zero-review.apex-event.v2`.
The existing `apex-trace-rs` store accepts only its legacy closed event shape, so v2
submission remains blocked until that separately owned contract and persistence layer
retain the producer identity, key ID, and signature. The compatibility test protects
the legacy shape only; it is not evidence that v2 authenticated events are accepted.

Ledger checkpoint verification uses current key validity. `created_at` is signed and
future-skew checked, but it is not treated as a trusted timestamp. Long-term
verification after key expiry requires an external timestamp or transparency witness;
until then, an expired or revoked key fails closed even for an older checkpoint.

No `v0.2.0` release or tag existed when packet v3 was introduced, so this pre-release
contract correction does not replace a published v0.2 API.
