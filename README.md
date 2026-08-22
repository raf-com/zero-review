# zero-codereview

`zero-codereview` is the evidence-first policy and integration layer above the existing review tools on this host. It inventories repository review controls, accepts normalized findings, computes a deterministic decision, invokes explicitly configured zero adapters, probes the Apex dispatch boundary, generates Mermaid topology, and writes hash-chained receipts.

It does not approve or merge pull requests, mutate GitHub, start Apex services, or convert an unverified finding into verified evidence.

## Control flow

```text
repository -> inventory -> zero-pr-review / zero-lint / zero-github
           -> normalized findings -> deterministic policy
           -> zero-proof / external oracle -> Apex trace/dispatch
           -> hash-chained receipt
```

## Commands

```powershell
cargo run -- inventory --repo C:\webapp_core --out artifacts\webapp-inventory.json
cargo run -- diagram --inventory artifacts\webapp-inventory.json --out artifacts\code-review-topology.mmd
cargo run -- evaluate --input review-input.json
cargo run -- adapter --program C:\zero-pr-review\target\debug\zero-pr-review.exe -- doctor
cargo run -- doctor --apex-url http://127.0.0.1:8009/health
cargo run -- apex-event --ledger artifacts\receipts.jsonl --out artifacts\apex-event.json
cargo run -- ledger-append --ledger artifacts\receipts.jsonl --operation inventory --subject C:\webapp_core --evidence artifacts\webapp-inventory.json
cargo run -- ledger-verify --ledger artifacts\receipts.jsonl
```

The Apex exporter produces an unsigned ExpertTraceEvent-compatible document. It does not sign or submit to the authenticated Apex trace sink.

Run scripts\install.ps1 for a locked release build and installed-binary smoke test. The package CI workflow runs formatting, strict Clippy, tests, and the security fixture on Windows.

## Evidence labels

- `verified`: current command or receipt supports the exact claim.
- `partial`: local behavior works but an external or end-to-end boundary remains.
- `blocked`: a required command or service failed or timed out.
- `owner_gated`: proof needs credentials, production data, or mutation authority.
- `not_proven`: configuration or prose exists without a current receipt.
