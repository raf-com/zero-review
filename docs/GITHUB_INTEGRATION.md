# GitHub integration contract

Consumer repositories configure `ZERO_REVIEW_RELEASE_URL`, `ZERO_REVIEW_SHA256`, and
`ZERO_REVIEW_CONTROL_CHECKS_JSON`. The control map uses
`zero-review.control-check-map.v1`; every applicable control maps to one or more
exact check names, GitHub App slugs, trusted workflow paths, and trigger events. A
name/App match from a different workflow is not evidence.

The consumer workflow binds repository, pull request, base SHA, head SHA, changed
paths, binary diff, applicability, security findings, prerequisite checks, and the
latest independent head-bound approval. Missing mappings, incomplete checks, stale
approvals, duplicate trusted check identities, and blocking findings fail closed.

Consumers must invoke this workflow by full commit SHA from an approved protected
revision. They must not pass a caller-selected tooling SHA. The called workflow
derives `github.workflow_sha` and accepts it only when it appears in the trusted
tooling allowlist; an unapproved branch, tag, or fork therefore fails closed.

The current consumer polls boundedly because its prerequisite workflow graph is owned
by the consumer repository. Once the canonical prerequisite jobs are identified,
the preferred deterministic arrangement is a terminal local job that calls a
commit-SHA-pinned reusable Zero Review workflow with `needs` on those jobs. Publishing
such a caller before the reusable workflow has a stable release SHA would create an
unverifiable dependency, so hosted adoption remains gated on the first immutable
release and repository ruleset configuration.

Example variable value:

```json
{"schema_version":"zero-review.control-check-map.v1","controls":{"tests":[{"name":"tests / unit","app_slug":"github-actions","workflow_path":".github/workflows/tests.yml","event":"pull_request"}],"security":[{"name":"security / scan","app_slug":"github-actions","workflow_path":".github/workflows/security.yml","event":"pull_request"}]}}
```

Acceptance requires a hosted negative run for absent or spoofed checks, a hosted
negative run without a current-head independent approval, a passing run with all
mapped checks, and ruleset readback proving the Zero Review check is required.

## Snapshot evaluator boundary

`scripts/github_consumer.py` is the deterministic policy core for a snapshot made
by a trusted collector. It does not collect or authenticate GitHub API responses.
Workflow path, event, check name, and App slug inside a supplied snapshot remain
producer claims. A release-capable collector must correlate each check to its
workflow run and prove that the executed workflow definition came from a protected
base/default-branch revision, then re-fetch the PR immediately before packet
emission. Until that collector and hosted negative cases exist, the script is
fixture-tested infrastructure and must not be configured as a required status
check.

## Protected workflow provenance requirement

`workflow_definition_sha` is necessary but not sufficient evidence. The collector
must retain each run's `workflow_id` and `referenced_workflows` records, then
compare the executed definition and every reusable-workflow SHA with the approved
workflow definition from the protected default-branch revision. A workflow file
fetched only from the pull-request head proves content identity, not protection.
Missing, mutable, mismatched, or unverifiable protected-definition evidence is
`not_proven` and must fail closed.
