# Apex and operations audit — 2026-09-05

This is a bounded local audit for work orders `ZR-R5-001` and `ZR-R6-001`. It records source-level controls and safe loopback probes only. It does not establish deployment, authenticated Apex submission, production readiness, or human approval.

## Apex boundary findings

The Rust Apex surface is fail-closed by construction:

- `ApexProducerAssertion` requires an explicit producer and key identifier plus a signature.
- `AuthenticatedApexEvent` can only be constructed through the verification path; signature verification failure returns an error.
- Event validation rejects unsupported schema versions, invalid identifiers, missing outcome status, and inconsistent decision/status combinations.
- `apex_event_from_receipt` refuses to generate an event without a release artifact and authenticated producer.
- The operations policy keeps Apex advisory and prohibits interpreting unsigned legacy events as authenticated v2 evidence.

Required external evidence remains outstanding: an owned/reviewed Apex trace service, authorized least-privilege producer identity, key lifecycle evidence, replay/nonce protection, signed checkpoint witness, and an authenticated round trip. No credentials were read and no dispatch was attempted.

## Safe endpoint probes

Probe command (PowerShell, three-second timeout, GET only):

```text
Invoke-WebRequest -UseBasicParsing -Uri <endpoint> -TimeoutSec 3
```

Observed on 2026-09-05 from this checkout:

| Endpoint | Result | Interpretation |
|---|---|---|
| `127.0.0.1:8009/health` | HTTP 200 (curl status probe) | health endpoint reachable; authenticated trace round-trip and dispatchability remain unproven |
| `127.0.0.1:8099/health` | timeout/failure | control-plane availability is not proven by this audit |
| `127.0.0.1:8093/health` | timeout/failure | control-plane availability is not proven by this audit |
| `127.0.0.1:8092/health` | timeout/failure | control-plane availability is not proven by this audit |

These results are environmental observations, not code defects. Re-probe before any availability or dispatch decision.

## Operations/adoption readiness

The repository already defines measurable pilot objectives in `OPERATIONS_POLICY.md` and the measurement contract in `PILOT_OPERATIONS.md`. Adoption remains staged:

1. local invocation and reconstructable receipts;
2. normal PR review and hosted run on the exact revision;
3. required status-check readback;
4. separately authorized Apex identity and round trip;
5. maintainer training and a 30-day evidence-backed exit review.

The following are not proven by this audit: hosted branch protection, independent approval, release-environment reviewers, runtime SLOs, adapter reliability over a real pilot window, external witness independence, or production readiness.

## Work-order disposition

| Work order | Disposition | Remaining gate |
|---|---|---|
| `ZR-R5-001` | source audit complete; local endpoint blocked | owner-authorized Apex identity, reachable reviewed sink, signed round trip |
| `ZR-R6-001` | readiness requirements documented | real pilot receipts, hosted readback, training, 30-day exit review |

Next safe actions are to preserve this audit with the review packet, re-run local probes immediately before any Apex action, and have the repository owner supply external receipts for the owner-gated items.
