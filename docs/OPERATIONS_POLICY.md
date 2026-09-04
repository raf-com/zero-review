# Zero Review operations policy

## Authority and merge policy

- Every change enters `main` through a pull request with required CI and an approval from a qualified person other than the last pusher.
- Do not bypass protection to resolve reviewer scarcity. Add at least two non-author maintainers before enabling required CODEOWNER review.
- Feature pull requests use squash merge. Force pushes and branch deletion remain disabled on `main`; merged topic branches are deleted automatically.
- Zero Review never supplies human approval and Apex remains advisory.

## Release policy

- Release only an annotated `vMAJOR.MINOR.PATCH` tag whose version matches `Cargo.toml` and whose commit is on protected `main`.
- The `release` environment is the publication boundary. Configure qualified required reviewers and prevent self-review before the first tag.
- Release assets are immutable. Publish Windows and Linux executables, manifests, checksums, dependency inventories, an SBOM, and GitHub build-provenance attestations.
- Consumers verify the repository, signer workflow, commit, attestation, and SHA-256. They never consume a mutable `latest` URL.
- CI artifacts are retained for 90 days. Release manifests, SBOMs, attestations, and externally witnessed ledger roots follow the release retention lifecycle.

## Apex policy

- No submission occurs until the trace service is reachable, its source has an owned Git remote and review controls, and the v2 schema migration is reviewed.
- Use a dedicated least-privilege producer identity. Prefer short-lived workload identity; otherwise keep Ed25519 private material outside Git and enforce validity, rotation, revocation, and nonce replay protection.
- Preserve legacy decoding only for a documented migration window. Never reinterpret an unsigned legacy event as authenticated v2 evidence.
- A local hash chain is not an external witness. Long-term audit claims require publication of signed checkpoint roots to an independently retained witness.

## Pilot and service levels

Pilot first on this repository, then on `webapp_core`. Record p50 and p95 review latency, queue time, adapter reliability, stale-evidence count, override count, false-positive dispositions, and blocked/not-proven causes. Pass rate is not a target.

Initial objectives, reviewed after 30 days of real observations:

- p95 control-plane evaluation under 10 minutes, excluding independent human review time.
- 99% successful adapter completion for enrolled deterministic adapters.
- zero accepted stale-head packets and zero accepted replayed overrides.
- every unavailable dependency represented as blocked or not-proven, never pass.

## Incident and rollback

- Compromised signing key: revoke the key, stop submission, preserve evidence, rotate credentials, and reissue only evidence that can be independently reproduced.
- Unavailable adapter or Apex: fail closed for required controls; Apex outage does not prevent local evidence generation but prevents an Apex round-trip claim.
- GitHub outage: do not merge through a bypass. Retain local evidence and rerun hosted checks after service restoration.
- Faulty Zero Review release: remove it from consumer configuration, restore the last attested digest, and open a reviewed corrective release. Never mutate an existing release.
