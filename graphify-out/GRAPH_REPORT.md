# Graph Report - zero-review  (2026-09-04)

## Corpus Check
- Corpus is ~6,556 words - fits in a single context window. You may not need a graph.

## Summary
- 248 nodes · 345 edges · 26 communities (23 shown, 3 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 24 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Infrastructure topology
- Serialized fields
- Evidence states
- Core review model
- Review policy flow
- CLI commands
- PR orchestration
- Ecosystem inventory
- Apex event contract
- Adoption roadmap
- Finding schema
- Bounded adapters
- Receipt ledger
- Review needs
- Owner-gated adoption
- Control discovery
- Control-plane purpose
- Application package
- Apex test package
- Evidence documentation

## God Nodes (most connected - your core abstractions)
1. `policy engine` - 16 edges
2. `main()` - 11 edges
3. `change surface and risk classification` - 11 edges
4. `append_receipt()` - 10 edges
5. `zero-review policy and receipt` - 10 edges
6. `ApexExpertTraceEvent` - 9 edges
7. `Finding` - 8 edges
8. `apex_event_from_receipt()` - 7 edges
9. `EvidenceStatus` - 7 edges
10. `ReviewInput` - 7 edges

## Surprising Connections (you probably didn't know these)
- `zero-review-ci` --implements--> `repository zero-review workflow`  [INFERRED]
  .github/workflows/ci.yml → docs/ARCHITECTURE.md
- `main()` --calls--> `apex_event_from_receipt()`  [INFERRED]
  src/main.rs → src/apex.rs
- `main()` --calls--> `inventory_repository()`  [INFERRED]
  src/main.rs → src/inventory.rs
- `main()` --calls--> `evaluate()`  [INFERRED]
  src/main.rs → src/policy.rs
- `main()` --calls--> `append_receipt()`  [INFERRED]
  src/main.rs → src/receipt.rs

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **docs_review_needs_review_dimensions** — docs_review_needs_correctness_tests, docs_review_needs_security_secrets, docs_review_needs_dependencies_supply_chain, docs_review_needs_data_migration_rollback, docs_review_needs_deployability_runbooks, docs_review_needs_observability, docs_review_needs_performance_capacity, docs_review_needs_product_accessibility, docs_review_needs_privacy_compliance, docs_review_needs_documentation_supportability, docs_architecture_policy_engine [EXTRACTED 1.00]
- **docs_ecosystem_map_review_capability_ecosystem** — docs_ecosystem_map_zero_security, docs_ecosystem_map_zero_specification, docs_ecosystem_map_zero_quality, docs_ecosystem_map_zero_benchmark, docs_ecosystem_map_zero_browser, docs_ecosystem_map_zero_artifact, docs_ecosystem_map_zero_memory, docs_ecosystem_map_zero_otel, docs_ecosystem_map_zero_perfmon, docs_ecosystem_map_zero_control, docs_ecosystem_map_zero_action, docs_ecosystem_map_zero_deploy, docs_ecosystem_map_zero_rollback, docs_ecosystem_map_apex_prod, docs_ecosystem_map_apex_evals, docs_ecosystem_map_apex_proofs, docs_ecosystem_map_apex_dag, docs_ecosystem_map_apex_event_engine, docs_ecosystem_map_apex_monitoring, docs_ecosystem_map_apex_dashboards, docs_ecosystem_map_apex_sdks, docs_ecosystem_map_apex_tests, docs_ecosystem_map_zero_review_policy_receipt [EXTRACTED 1.00]

## Communities (26 total, 3 thin omitted)

### Community 0 - "Infrastructure topology"
Cohesion: 0.07
Nodes (28): Apex trace sink, branch protection, merge, SHA-bound review artifacts, zero-commit, apex_dag, apex_dashboards, apex_evals (+20 more)

### Community 1 - "Serialized fields"
Cohesion: 0.09
Nodes (24): id, severity, source, status, summary, items, type, items (+16 more)

### Community 2 - "Evidence states"
Cohesion: 0.09
Nodes (22): block, blocked, info, not_proven, owner_gated, partial, verified, warning (+14 more)

### Community 3 - "Core review model"
Cohesion: 0.21
Nodes (16): Control, Decision, default_schema_version(), EvidenceStatus, Finding, Inventory, Receipt, ReviewDecision (+8 more)

### Community 4 - "Review policy flow"
Cohesion: 0.18
Nodes (18): independent human review, normalized findings v1, policy engine, zero-lint, zero-pr-review, zero-risk, change surface and risk classification, correctness and tests review (+10 more)

### Community 5 - "CLI commands"
Cohesion: 0.17
Nodes (13): Cli, Commands, emit(), main(), Option, PathBuf, Result, String (+5 more)

### Community 6 - "PR orchestration"
Cohesion: 0.13
Nodes (15): GitHub pull request, inventory repository controls, repository zero-review workflow, review-needs catalog, zero-github, zero-workflow, zero-action, zero-control (+7 more)

### Community 7 - "Ecosystem inventory"
Cohesion: 0.30
Nodes (14): EcosystemConfig, EcosystemInventory, EcosystemRoot, EcosystemRootConfig, git(), inventory_ecosystem(), missing_root_is_not_proven(), node_id() (+6 more)

### Community 8 - "Apex event contract"
Cohesion: 0.29
Nodes (12): apex_event_from_receipt(), ApexEvaluationStatus, ApexEventType, ApexExpertTraceEvent, ApexOutcomeStatus, ApexPolicyDecision, receipt_maps_to_valid_apex_outcome(), Option (+4 more)

### Community 9 - "Adoption roadmap"
Cohesion: 0.18
Nodes (12): refreshable ecosystem inventory, checksum-pinned release artifacts, review operational SLOs, signed review-packet manifest, Stage 0 inventory baseline, Stage 1 canonical contracts, Stage 2 applicability and orchestration, Stage 3 evidence and policy engine (+4 more)

### Community 10 - "Finding schema"
Cohesion: 0.20
Nodes (9): findings, repository, schema_version, additionalProperties, $id, required, $schema, title (+1 more)

### Community 11 - "Bounded adapters"
Cohesion: 0.29
Nodes (9): AdapterResult, bounded_adapter_reports_timeout(), probe(), Option, Path, Result, String, run() (+1 more)

### Community 12 - "Receipt ledger"
Cohesion: 0.33
Nodes (8): append_receipt(), detects_tampering(), digest(), Path, Result, String, Vec, verify_ledger()

### Community 13 - "Review needs"
Cohesion: 0.39
Nodes (7): ReviewNeed, catalog_has_unique_ids_and_human_approval(), need(), review_needs(), review_needs_diagram(), String, Vec

### Community 14 - "Owner-gated adoption"
Cohesion: 0.40
Nodes (5): authorized Apex producer identity, hosted pull-request run, maintainer training, repository-local workflow, required zero-review status check

### Community 15 - "Control discovery"
Cohesion: 0.60
Nodes (4): excludes_worktrees_and_discovers_executable_controls(), inventory_repository(), Path, Result

### Community 16 - "Control-plane purpose"
Cohesion: 0.50
Nodes (4): unsigned Apex-compatible advisory events, fail-closed policy, hash-chained local receipt ledger, zero-review Rust review control plane

## Knowledge Gaps
- **75 isolated node(s):** `zero-review`, `zero-review-apex-compat`, `$schema`, `$id`, `title` (+70 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `policy engine` connect `Review policy flow` to `Infrastructure topology`?**
  _High betweenness centrality (0.008) - this node is a cross-community bridge._
- **Why does `independent human review` connect `Review policy flow` to `Infrastructure topology`?**
  _High betweenness centrality (0.007) - this node is a cross-community bridge._
- **Are the 8 inferred relationships involving `main()` (e.g. with `apex_event_from_receipt()` and `inventory_repository()`) actually correct?**
  _`main()` has 8 INFERRED edges - model-reasoned connections that need verification._
- **What connects `zero-review`, `zero-review-apex-compat`, `$schema` to the rest of the system?**
  _75 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Infrastructure topology` be split into smaller, more focused modules?**
  _Cohesion score 0.07407407407407407 - nodes in this community are weakly interconnected._
- **Should `Serialized fields` be split into smaller, more focused modules?**
  _Cohesion score 0.08695652173913043 - nodes in this community are weakly interconnected._
- **Should `Evidence states` be split into smaller, more focused modules?**
  _Cohesion score 0.09090909090909091 - nodes in this community are weakly interconnected._