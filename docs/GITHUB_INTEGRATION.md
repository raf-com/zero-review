# GitHub integration contract

Consumer repositories configure `ZERO_REVIEW_RELEASE_URL`, `ZERO_REVIEW_SHA256`, and
`ZERO_REVIEW_CONTROL_CHECKS_JSON`. The control map uses
`zero-review.control-check-map.v1`; every applicable control maps to one or more
exact check names and GitHub App slugs. A name match from another App is not evidence.

The consumer workflow binds repository, pull request, base SHA, head SHA, changed
paths, binary diff, applicability, security findings, prerequisite checks, and the
latest independent head-bound approval. Missing mappings, incomplete checks, stale
approvals, duplicate trusted check identities, and blocking findings fail closed.

The current consumer polls boundedly because its prerequisite workflow graph is owned
by the consumer repository. Once the canonical prerequisite jobs are identified,
the preferred deterministic arrangement is a terminal local job that calls a
commit-SHA-pinned reusable Zero Review workflow with `needs` on those jobs. Publishing
such a caller before the reusable workflow has a stable release SHA would create an
unverifiable dependency, so hosted adoption remains gated on the first immutable
release and repository ruleset configuration.

Example variable value:

```json
{"schema_version":"zero-review.control-check-map.v1","controls":{"tests":[{"name":"tests / unit","app_slug":"github-actions"}],"security":[{"name":"security / scan","app_slug":"github-actions"}]}}
```

Acceptance requires a hosted negative run for absent or spoofed checks, a hosted
negative run without a current-head independent approval, a passing run with all
mapped checks, and ruleset readback proving the Zero Review check is required.
