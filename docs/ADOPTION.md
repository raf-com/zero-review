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
