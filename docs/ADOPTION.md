# Adoption and socialization

Adoption is a sequence of separately provable controls:

1. Add the repository-local workflow and runner script.
2. Run it locally against the intended repository and retain its artifacts.
3. Push the workflow through normal review.
4. Observe a hosted pull-request run on the exact workflow revision.
5. Configure `zero-review` as a required status check and verify branch-protection readback.
6. Register an authorized Apex producer identity before signing or submitting advisory events.
7. Train maintainers on finding severity, evidence states, overrides, and incident handling.

This checkout proves only what its current local test receipts show. Steps 3-7 require repository-owner or external-system evidence.

## Receipt map and ownership

| Adoption gate | Required receipt | System boundary | Decision owner |
|---|---|---|---|
| Local readiness | serial test, security, and packet receipts bound to a commit | source/local | implementer, then maintainer |
| Hosted readiness | successful run and check conclusion on the exact head SHA | GitHub Actions | repository owner |
| Protection readiness | current branch-protection/ruleset readback | GitHub administration | repository owner |
| Pilot entry | enrolled adapter list, observation window, rollback owner, retention confirmation | local + hosted | maintainer |
| Pilot exit | raw receipt index, aggregate, incidents, exclusions, objective dispositions | local evidence | independent reviewer |
| Apex readiness | authenticated producer, trusted sink, replay protection, signed round trip | external runtime | repository owner |
| Release readiness | protected-main ancestry, tag/version match, attestations, consumer verification | GitHub release | release authority |

No row is satisfied by a prose status file. A missing external receipt is recorded as `blocked` or `not_proven`, not inferred from a passing local test.
