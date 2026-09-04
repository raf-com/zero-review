# Review needs

Every PR must produce a review packet bound to its base and head SHA. Applicability is path/risk driven. Change-scope and independent human approval are global controls; correctness, security, dependency, and specialist controls fail closed whenever routing marks them applicable and their evidence is absent.

```mermaid
flowchart TB
  CHANGE[Changed paths plus base/head SHA] --> CLASSIFY[Classify surfaces and risk]
  CLASSIFY --> CODE[Correctness and tests]
  CLASSIFY --> SEC[Security and secrets]
  CLASSIFY --> SUPPLY[Dependencies and supply chain]
  CLASSIFY --> DATA[Schema, data, migration and rollback]
  CLASSIFY --> OPS[Deployability, rollback and runbooks]
  CLASSIFY --> OBS[Logs, metrics, traces and alerts]
  CLASSIFY --> PERF[Performance and capacity]
  CLASSIFY --> UX[Product, browser and accessibility]
  CLASSIFY --> PRIV[Privacy and compliance]
  CLASSIFY --> DOCS[Documentation and supportability]
  CODE --> DECIDE[Fail-closed policy decision]
  SEC --> DECIDE
  SUPPLY --> DECIDE
  DATA --> DECIDE
  OPS --> DECIDE
  OBS --> DECIDE
  PERF --> DECIDE
  UX --> DECIDE
  PRIV --> DECIDE
  DOCS --> DECIDE
  DECIDE --> HUMAN[Independent human review]
  HUMAN --> RECEIPT[Review receipt bound to head SHA]
```

The machine-readable catalog is produced by `zero-review needs`. Review evidence must include commands, exit codes, artifact paths, and the reviewed SHA; prose-only completion statements are `not_proven`.
