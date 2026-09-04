# Review infrastructure topology

This diagram describes source-level integration. A node is not live merely because it appears here.

```mermaid
flowchart LR
  DEV[Developer change] --> PR[GitHub pull request]
  PR --> WF[Repository zero-review workflow]
  WF --> BUILD[Build zero-review from Cargo.lock]
  WF --> INV[Inventory repository controls]
  WF --> NEEDS[Publish review-needs catalog]
  WF --> TESTS[Repository tests and specialist checks]
  WF --> REGISTRY[Digest-pinned adapter registry and exact arguments]
  REGISTRY --> TESTS
  INV --> POLICY[Fail-closed policy engine]
  NEEDS --> POLICY
  TESTS --> NORMALIZE[Normalized findings v1]
  NORMALIZE --> POLICY
  POLICY --> RECEIPT[Typed evidence artifacts and locked hash chain]
  POLICY --> HUMAN[Independent human review]
  RECEIPT --> PROOF[Zero proof and evidence consumers]
  RECEIPT --> APEX[Apex local unsigned advisory export]
  APEX -. authenticated submission requires owner identity .-> TRACE[Apex trace sink]
  HUMAN --> PROTECT[Required status check and branch protection]
  RECEIPT --> PROTECT
  PROTECT --> MERGE[Merge]

  ZPR[zero-pr-review] --> NORMALIZE
  ZL[zero-lint] --> NORMALIZE
  ZG[zero-github] --> INV
  ZR[zero-risk] --> POLICY
  ZC[zero-commit] --> RECEIPT
  ZW[zero-workflow] --> WF
```

## Trust boundaries

1. Repository code and PR metadata are untrusted inputs.
2. Adapter output is advisory until normalized and bound to the reviewed head SHA.
3. Apex export is unsigned by default; authenticated submission is owner-gated.
4. A local pass does not prove the hosted workflow or branch-protection rule executed.
5. Human approval remains mandatory for merge; the tool never self-approves.
6. Built-in security pattern results remain `not_proven` for specialist coverage.
7. Override signing, replay protection, and authenticated Apex producer identity remain owner-gated.
