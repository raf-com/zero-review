# zero-review

`zero-review` is the Rust review control plane for pull requests. It inventories repository controls, publishes the review-needs catalog, evaluates normalized findings with fail-closed policy, invokes explicitly configured Zero adapters, emits unsigned Apex-compatible advisory events, and keeps a hash-chained local receipt ledger.

It does not merge or approve pull requests, sign Apex events, bypass human review, or prove GitHub branch protection. Those boundaries remain external and must provide their own current receipts.

## Local commands

```powershell
cargo run --locked -- needs --out artifacts\review-needs.json --diagram artifacts\review-needs.mmd
cargo run --locked -- inventory --repo C:\webapp_core --out artifacts\webapp-core-inventory.json
cargo run --locked -- diagram --inventory artifacts\webapp-core-inventory.json --out artifacts\infrastructure.mmd
cargo run --locked -- evaluate --input tests\fixtures\review-pass.json
cargo run --locked -- doctor --apex-url http://127.0.0.1:8009/health
cargo run --locked -- ledger-verify --ledger artifacts\receipts.jsonl
```

## Evidence states

- `verified`: current command or receipt supports the exact claim.
- `partial`: local behavior works but an external boundary is open.
- `blocked`: a required command or service failed or timed out.
- `owner_gated`: credentials, protected settings, production data, or mutation authority are required.
- `not_proven`: configuration or prose exists without a current receipt.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/REVIEW_NEEDS.md](docs/REVIEW_NEEDS.md), and [docs/ADOPTION.md](docs/ADOPTION.md).
