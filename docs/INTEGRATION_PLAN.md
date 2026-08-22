# Code-review infrastructure integration plan

## Current topology

| Layer | Current surface | Package role | Evidence boundary |
|---|---|---|---|
| Repository controls | `webapp_core/.github/workflows`, `scripts/`, config | inventory and normalize | discovery is not execution |
| PR acquisition | `zero-pr-review`, `zero-github` | invoke explicit read-only adapters | GitHub writes remain disallowed |
| Deterministic checks | `zero-lint`, repository-native lint/test commands | collect findings | a command receipt is required |
| Decision | `zero-codereview` | deterministic block/review/pass policy | pass requires verified inputs |
| Proof | `zero-proof`, code-sentinel oracle | verify exact claims | proof scope must match claim |
| Trace and dispatch | `apex-trace-rs`, Apex `:8009` | health/preflight and future trace export | dispatch requires non-quiesced workers |
| Evidence | JSON artifacts and hash-chained ledger | durable receipts | ledger integrity is not product correctness |

## Needs

1. Add repository-local automation that invokes `zero-codereview inventory` and `evaluate`.
2. Define a versioned normalized judgment schema for human or agent findings.
3. Expand repository-native command adapters beyond the current bounded executable adapter.
4. Authenticate and sign exported Apex events only after a producer key and sink authority are provided.
5. Keep merge and GitHub mutation outside the package until separately authorized.
6. Re-run Apex preflight before dispatch; reachable but quiesced is blocked.
7. Add fixture-backed tests for inventory exclusion and adapter timeout behavior.

## Integration statuses

- Rust build and local policy tests: verified by a current local command.
- `webapp_core` static inventory and topology generation: partial; discovered controls are not executed by inventory.
- `zero-pr-review` adapter and GitHub authentication: verified by a current adapter command.
- Apex health: verified reachable at the health endpoint.
- Apex dispatch: blocked because the dispatcher reports quiesced and zero dispatchable workers.
- Apex event shape: verified against the actual trace_store ExpertTraceEvent type by the local compatibility test.
- Release installer: verified locally; hosted CI execution remains not proven.
- Local CI-equivalent runner: verified across formatting, strict Clippy, package tests, security fixture, and the Apex compatibility test.
- Repository-local CI invocation: not proven until a workflow or local target executes the package.
