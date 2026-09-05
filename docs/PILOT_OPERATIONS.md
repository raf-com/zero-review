# Pilot operations

This document defines the measurement contract before a Zero Review pilot starts. It does not establish that a pilot, service, external witness, or objective is operational.

## Observation boundary

One `pilot-metrics-v1` document covers one repository, one named pilot, and a closed UTC window. `window_ended_at` must not precede `window_started_at`, and `generated_at` must not precede the window end. Producers must enforce these chronological constraints because JSON Schema validates representation, not ordering between timestamps.

Use `pre_pilot` when exercising the aggregation code with fixtures. Use `observed` only when every included count and sample can be reconstructed from the listed immutable source receipts. Use `partial` when some real observations are supported but the window is incomplete. Use `not_proven` when source provenance, completeness, or integrity cannot be established. Empty fixture output is not an observed zero.

## Counters and denominators

Counters are monotonically summed within a window. They must not be inferred from missing events.

- Adapter reliability is `adapter_successes / adapter_attempts`; an attempt has exactly one terminal success or non-success outcome. With zero attempts, reliability is undefined, not 100%.
- Evaluation completion is `evaluations_completed / evaluations_started`. Human review time is not part of control-plane evaluation latency.
- Stale evidence and replay counters distinguish detection from acceptance. An accepted count of zero is supportable only with complete inputs and trusted source receipts.
- A false-positive disposition is counted only after a recorded human disposition identifies the control and reason. Pass rate is not a pilot target.
- `blocked_decisions` and `not_proven_decisions` must equal the sums of their respective cause maps. Cause identifiers are stable lowercase machine keys; descriptive text belongs in the source receipt.

## Latency aggregation

Control-plane latency begins when an evaluation is accepted by the enrolled runner and ends when its terminal decision is durably recorded. Queue latency begins at the eligible trigger timestamp and ends when evaluation begins. Store integer milliseconds.

Compute p50 and p95 independently from the complete samples in the window using the nearest-rank method. Set both percentile fields to `null` when `sample_count` is zero. Do not mix fixtures, retries, human review time, or observations from another repository. Raw observations remain the source of truth; aggregates are reproducible summaries.

## Source receipts and retention

Each aggregate lists the identifier and SHA-256 of every immutable source receipt used to derive it. The aggregator must reopen those receipts, verify their hashes, reject duplicates, and fail closed on missing or malformed input. The schema alone does not perform those checks.

Retain raw pilot receipts and each aggregate for at least 90 days. Release-linked receipts, manifests, attestations, and witnessed checkpoints follow the release retention lifecycle and must not be shortened by pilot cleanup. Minimize personal data and secrets; use stable opaque identifiers where correlation is required.

## Witness checkpoints

`witness-checkpoint-v1` is an envelope around a Zero Review ledger checkpoint and an independently retained receipt. `checkpoint_sha256` binds the exact canonical checkpoint bytes, while `last_entry_hash` and `entry_count` bind the ledger position. `witness_receipt.sha256` binds the retrieved witness artifact; `locator` identifies where an auditor can obtain it.

`receipt_observed` proves only that an artifact was retrieved and hash-matched. `signature_verified` additionally requires successful Ed25519 verification against an independently trusted witness key. `not_proven` is required when independence, retention, key trust, signature validity, or retrieval cannot be established. Self-hosting a receipt beside the ledger is not external witnessing.

The envelope does not prove that the witness is independent, that the locator remains available, or that either digest was calculated correctly. Those are runtime verification obligations with receipts of their own.

## Pilot exit review

After 30 days of real, reconstructable observations, review the objectives in `OPERATIONS_POLICY.md`. A decision must report the window, sample counts, exclusions, source receipt set, and all blocked or not-proven causes. No objective passes solely because an aggregate conforms to its schema.

## Entry and exit checklist

The following checklist is the acceptance contract for work orders 20-15 and
20-16. Each line must point to a content-addressed receipt (or explicitly be
marked `blocked`/`not_proven`); a checkbox or prose assertion is not evidence.

### Entry packet (`pilot-entry-v1`)

| Item | Required evidence | Fail-closed condition |
| --- | --- | --- |
| Identity | repository, base SHA, head SHA, generated-at UTC | any missing or non-40-character SHA |
| Scope | named controls, adapters, exclusions, observation window | scope differs between packet and source receipts |
| Safety | rollback owner, retention location, expiry/cleanup policy | no named owner or retention location |
| Determinism | local test receipt bound to the exact head SHA | receipt is stale, malformed, or head-mismatched |
| Hosted boundary | successful hosted run and current protection readback | either receipt is absent or stale |

Entry is `pass` only when all rows have verified receipts. Otherwise the
pilot remains `blocked` or `not_proven` and observation counts must not be
reported as production results.

### Exit packet (`pilot-exit-v1`)

| Item | Required evidence | Fail-closed condition |
| --- | --- | --- |
| Completeness | closed UTC window and raw receipt index | window is open or a source receipt is missing |
| Integrity | reopened SHA-256 verification with duplicate rejection | any hash mismatch, duplicate, or malformed receipt |
| Outcomes | aggregate counts reconstructable from raw receipts | aggregate cannot be independently recomputed |
| Exceptions | excluded-event list, incidents, blocked/not-proven causes | unexplained exclusion or cause-count mismatch |
| Review | explicit disposition per objective and reviewer identity | system-generated output is treated as human review |

Exit is `pass` only when every objective has a supported disposition and all
exceptions are accounted for. Exit never authorizes release, deployment, or
Apex submission.

Pilot entry is a gate, not a calendar date. The packet must contain the exact repository, base and head commit, enrolled adapters, control set, observation window, retention location, rollback owner, and a successful local deterministic test receipt. Hosted workflow status and branch-protection readback are separate entry receipts; a local pass cannot substitute for either.

Exit requires a canonical aggregate plus the raw receipt index, hash verification results, excluded-event list, incident list, and an explicit disposition for every objective: `pass`, `partial`, `blocked`, or `not_proven`. An objective is `blocked` when a required dependency was unavailable; it is `not_proven` when evidence exists but cannot establish completeness, independence, or authenticity. The exit reviewer records the decision and reviewer identity separately from the system-generated packet. No exit decision authorizes release, deployment, or Apex submission.

Minimum incident evidence includes detection timestamp, affected control or adapter, first known bad revision, last known good revision, scope, containment action, preserved receipt hashes, recovery verification, and owner disposition. Rollback evidence must identify the restored attested digest and must not mutate an existing release.
