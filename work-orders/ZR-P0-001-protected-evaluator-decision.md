# ZR-P0-001 — Protected evaluator decision record

## Decision required

Select one immutable trust model for the review consumer:

1. **Preferred:** invoke the reusable consumer workflow from a full commit SHA that is protected on `main` and separately verify that SHA before running collector/consumer code.
2. **Acceptable fallback:** invoke a signed, immutable release tag whose commit ancestry and attestation are verified against the protected repository.
3. **Reject:** branch references, mutable tags, or caller-provided `trusted_tooling_sha` accepted without independent protected-reference verification.

## Owner actions

- Publish the complete evaluator tree (`consumer-review.yml`, collector, consumer, schemas, pin map) on protected `main` or an attested release.
- Configure callers to reference that immutable SHA.
- Read back branch/ruleset protection and retain the API response as evidence.
- Provide one independent reviewer identity for the pilot.

## Acceptance evidence

- Caller workflow reference and resolved commit SHA.
- Protected branch/ruleset readback showing required checks and review rules.
- Collector snapshot containing workflow run ID, workflow ID, path, event, head SHA, and definition SHA.
- Adversarial negative receipt proving a PR cannot replace its evaluator.

Until these receipts exist, status is `owner_gated` and the consumer may not be treated as a complete trust boundary.
