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
