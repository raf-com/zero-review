use crate::model::ReviewNeed;

pub fn review_needs() -> Vec<ReviewNeed> {
    vec![
        need(
            "change-scope",
            "Change scope and ownership",
            "PR author",
            &["all"],
            &["base/head SHA", "changed paths", "declared intent"],
            true,
        ),
        need(
            "tests",
            "Automated correctness",
            "test owner",
            &["code", "config"],
            &["test command", "exit code", "test artifact"],
            true,
        ),
        need(
            "security",
            "Security and secret exposure",
            "security reviewer",
            &["code", "dependencies", "infrastructure"],
            &["scanner output", "threat-boundary review"],
            true,
        ),
        need(
            "dependencies",
            "Dependency and supply chain",
            "dependency owner",
            &["lockfiles", "build tooling"],
            &["lockfile audit", "license policy", "provenance"],
            true,
        ),
        need(
            "data-migrations",
            "Schema and data migration safety",
            "data owner",
            &["migrations", "models", "backfills"],
            &["forward plan", "rollback plan", "backup evidence"],
            true,
        ),
        need(
            "operations",
            "Deployment and rollback operability",
            "operations owner",
            &["runtime", "deployment", "infrastructure"],
            &["deployment plan", "rollback trigger", "runbook delta"],
            true,
        ),
        need(
            "observability",
            "Telemetry and failure detection",
            "service owner",
            &["runtime", "performance"],
            &["metrics/logs/traces delta", "alert impact"],
            false,
        ),
        need(
            "performance",
            "Performance and capacity",
            "performance reviewer",
            &["hot paths", "queries", "assets"],
            &["baseline", "bounded benchmark", "regression threshold"],
            false,
        ),
        need(
            "product-ux",
            "Product, accessibility, and UX",
            "product reviewer",
            &["user-facing"],
            &[
                "acceptance criteria",
                "browser evidence",
                "accessibility evidence",
            ],
            true,
        ),
        need(
            "privacy-compliance",
            "Privacy and compliance",
            "compliance owner",
            &["personal data", "payments", "moderation"],
            &["data-flow impact", "retention impact", "control mapping"],
            true,
        ),
        need(
            "documentation",
            "Documentation and supportability",
            "maintainer",
            &["interfaces", "operations", "behavior"],
            &["docs delta or explicit no-change reason"],
            false,
        ),
        need(
            "human-approval",
            "Independent human approval",
            "CODEOWNER/reviewer",
            &["all"],
            &["review identity", "review state", "reviewed SHA"],
            true,
        ),
    ]
}

fn need(
    id: &str,
    title: &str,
    owner: &str,
    required_for: &[&str],
    evidence: &[&str],
    blocking: bool,
) -> ReviewNeed {
    ReviewNeed {
        id: id.into(),
        title: title.into(),
        owner: owner.into(),
        required_for: required_for.iter().map(|v| (*v).into()).collect(),
        evidence: evidence.iter().map(|v| (*v).into()).collect(),
        blocking,
    }
}

pub fn review_needs_diagram() -> String {
    let mut graph =
        String::from("flowchart LR\n  PR[Pull request] --> SCOPE[Classify changed surfaces]\n");
    for need in review_needs() {
        graph.push_str(&format!(
            "  SCOPE --> N_{}[\"{}\\nowner: {}\"]\n",
            need.id.replace('-', "_"),
            need.title.replace('"', "'"),
            need.owner
        ));
        graph.push_str(&format!(
            "  N_{} --> DECISION[Fail-closed decision]\n",
            need.id.replace('-', "_")
        ));
    }
    graph.push_str("  DECISION --> RECEIPT[SHA-bound review receipt]\n  RECEIPT --> APEX[Apex advisory trace]\n  RECEIPT --> MERGE[Merge protection / human approval]\n");
    graph
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_has_unique_ids_and_human_approval() {
        let needs = review_needs();
        let mut ids: Vec<_> = needs.iter().map(|n| n.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), needs.len());
        assert!(needs.iter().any(|n| n.id == "human-approval" && n.blocking));
    }
}
