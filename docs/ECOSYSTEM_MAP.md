# Zero and Apex review-support ecosystem

The refreshable source inventory is `artifacts/ecosystem-inventory.json`; it records filesystem and Git facts only. Root existence is classified `source_only`, not runtime-ready or integrated. Consumers must compare a stored inventory with a fresh inventory through `ecosystem::detect_drift`, set an explicit maximum age, and fail closed on stale snapshots, missing or removed roots, path renames, duplicate canonical paths, newly registered roots, or Git HEAD drift.

Discovery is bounded by explicit parent directories, name prefixes, exclusions, and a candidate ceiling in `config/ecosystem-roots.json`. Unregistered candidates are reported separately and never inherit capabilities merely from their name. Root identity includes canonical path, Git common directory, branch, HEAD, dirty state, and a SHA-256 digest of the origin URL; inventory and drift results carry configuration and snapshot digests.

Adapter executables are copied into a per-run private workspace, the execution copy is SHA-256 verified, and only that verified copy is launched. Output files are created exclusively, bounded when read, and removed with cleanup errors returned to the caller. Unix permissions are restricted to the current user; Windows confidentiality still depends on the temp-directory ACL inherited from the service account.

The registry-first API is `adapter::run_registered_file`; it accepts only a registry path, adapter ID, and exact allowlisted arguments. `config/adapter-registry.json` is intentionally empty until executable paths and current digests are enrolled. Windows DACL creation and process-tree Job Object containment require a Windows API dependency and remain fail-closed integration work; the current implementation rejects reparse-point executables but cannot claim those two OS controls.

## Capability topology

```mermaid
flowchart TB
  PR[Pull request plus base/head SHA] --> ZREV[zero-review policy and receipt]

  subgraph INPUTS[Repository and PR inputs]
    W[webapp_core workflows]
    ZBR[zero-branch]
    ZGH[zero-github]
    ZCOM[zero-commit]
  end

  subgraph ANALYSIS[Analysis and assurance]
    ZPR[zero-pr-review]
    ZL[zero-lint]
    ZSEC[zero-security]
    ZRISK[zero-risk]
    ZSPEC[zero-specification]
    ZQUAL[zero-quality]
    ZBENCH[zero-benchmark]
    ZBROW[zero-browser]
  end

  subgraph EVIDENCE[Evidence and provenance]
    ZPROOF[zero-proof]
    ZART[zero-artifact]
    ZMEM[zero-memory]
    ZOTEL[zero-otel]
    ZPERF[zero-perfmon]
  end

  subgraph CONTROL[Execution boundaries]
    ZCTRL[zero-control]
    ZACT[zero-action]
    ZWF[zero-workflow]
    ZDEP[zero-deploy]
    ZROLL[zero-rollback]
  end

  subgraph APEX[Apex advisory and evaluation]
    AP[apex-prod orchestration]
    ATR[apex-trace-rs]
    AE[apex_evals]
    APR[apex_proofs]
    ADAG[apex_dag]
    AEV[apex_event_engine]
    AMON[apex_monitoring]
    ADASH[apex_dashboards]
    ASDK[apex_sdks]
    ATEST[apex_tests]
  end

  W -. candidate .-> PR
  ZBR -. source-only .-> ZREV
  ZGH -. source-only .-> ZREV
  ZCOM -. source-only .-> ZREV
  PR -. candidate .-> ZPR
  ZPR -. source-only .-> ZREV
  ZL -. source-only .-> ZREV
  ZSEC -. source-only .-> ZREV
  ZRISK -. source-only .-> ZREV
  ZSPEC -. source-only .-> ZREV
  ZQUAL -. source-only .-> ZREV
  ZBENCH -. source-only .-> ZREV
  ZBROW -. source-only .-> ZREV
  ZREV -. candidate .-> ZPROOF -. candidate .-> ZART
  ZREV -. candidate .-> ZMEM
  ZREV -. candidate .-> ZOTEL -. candidate .-> ZPERF
  ZREV -. candidate .-> ZCTRL -. candidate .-> ZACT -. candidate .-> ZWF
  ZWF -. candidate .-> ZDEP -. candidate .-> ZROLL
  ZREV -. local unsigned export only .-> ATR -. owner-gated submission .-> AP
  AP -. source-only .-> ADAG -. source-only .-> AEV
  AP -. source-only .-> AE
  AP -. source-only .-> APR
  ATR -. source-only .-> AMON -. source-only .-> ADASH
  ASDK -. source-only .-> AP
  ATEST -. source-only .-> AP
```

## Review-need coverage

| Review need | Primary capability roots | Required future proof |
|---|---|---|
| Change scope and ownership | zero-branch, zero-github, zero-commit | PR metadata bound to immutable base/head SHAs |
| Automated correctness | zero-pr-review, zero-quality, apex_tests | Focused and affected-suite receipts |
| Security | zero-security, zero-lint, zero-risk | Diff/history scan plus reviewed threat-boundary findings |
| Dependencies and supply chain | zero-artifact, apex_sdks, zero-proof | Lockfile, provenance, license, and advisory receipts |
| Data and migrations | zero-risk, zero-rollback, zero-proof | Disposable forward/rollback rehearsal and backup evidence |
| Operations and rollback | zero-control, zero-deploy, zero-rollback | Release plan, approval, health and rollback receipts |
| Observability | zero-otel, zero-perfmon, apex_monitoring | Trace correlation, logs/metrics delta, alert validation |
| Performance | zero-benchmark, zero-perfmon, apex_evals | Reproducible baseline and regression threshold |
| Product, browser and accessibility | zero-browser, zero-pr-review | Deterministic journey and accessibility evidence |
| Privacy and compliance | zero-security, zero-risk, zero-specification | Data-flow, retention, authorization and control mapping |
| Documentation | zero-memory, zero-artifact | Versioned interface/runbook delta or justified no-change |
| Human approval | zero-github, zero-control, apex-trace-rs | Independent reviewer identity and approval bound to head SHA |

## Boundary diagram

```mermaid
sequenceDiagram
  participant Repo as Repository/PR
  participant Review as zero-review
  participant Zero as Zero specialist adapters
  participant Apex as Apex advisory plane
  participant Human as Independent reviewer
  participant GitHub as Merge protection
  Repo->>Review: base SHA, head SHA, changed paths
  Review->>Zero: bounded read-only analysis requests
  Zero-->>Review: normalized findings plus evidence
  Review->>Review: deterministic fail-closed decision
  Review-->>Apex: local unsigned advisory export; submission not active
  Review-->>Human: review packet and unresolved gates
  Human-->>GitHub: approve or request changes
  Review-->>GitHub: required status result
  Note over Apex,GitHub: Signing, submission and protection configuration require owner authority
```
