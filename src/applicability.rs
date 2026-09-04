//! Deterministic changed-path applicability routing.
//!
//! This module intentionally has no crate-local dependencies so its routing
//! contract can be tested before it is wired into the control-plane entrypoint.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const REVIEW_NEED_IDS: [&str; 12] = [
    "change-scope",
    "tests",
    "security",
    "dependencies",
    "data-migrations",
    "operations",
    "observability",
    "performance",
    "product-ux",
    "privacy-compliance",
    "documentation",
    "human-approval",
];

pub const MANDATORY_GLOBAL_CONTROLS: [&str; 2] = ["change-scope", "human-approval"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathApplicability {
    pub path: String,
    pub review_needs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicabilityRoute {
    /// Normalized, de-duplicated paths in lexical order.
    pub changed_paths: Vec<String>,
    /// The union of all applicable needs, including global controls.
    pub review_needs: Vec<String>,
    /// Per-path reasons, ordered by normalized path.
    pub path_applicability: Vec<PathApplicability>,
}

/// Routes changed repository-relative paths to review needs.
///
/// Matching is case-insensitive and accepts either path separator. Unknown
/// files are treated as application changes instead of silently escaping the
/// correctness, security, and documentation review baseline.
pub fn route_changed_paths<I, S>(paths: I) -> ApplicabilityRoute
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let normalized: BTreeSet<String> = paths
        .into_iter()
        .filter_map(|path| normalize_path(path.as_ref()))
        .collect();

    let mut routed = BTreeMap::new();
    let mut all_needs: BTreeSet<&'static str> = MANDATORY_GLOBAL_CONTROLS.into_iter().collect();

    for path in &normalized {
        let path_needs = needs_for_path(path);
        all_needs.extend(path_needs.iter().copied());
        routed.insert(path.clone(), sorted_strings(path_needs));
    }

    ApplicabilityRoute {
        changed_paths: normalized.into_iter().collect(),
        review_needs: sorted_strings(all_needs),
        path_applicability: routed
            .into_iter()
            .map(|(path, review_needs)| PathApplicability { path, review_needs })
            .collect(),
    }
}

fn normalize_path(path: &str) -> Option<String> {
    let normalized = path.trim().replace('\\', "/");
    let normalized = normalized.trim_start_matches("./").trim_matches('/');
    (!normalized.is_empty()).then(|| normalized.to_ascii_lowercase())
}

fn needs_for_path(path: &str) -> BTreeSet<&'static str> {
    let mut needs = BTreeSet::new();
    needs.extend(["tests", "security", "documentation"]);

    let file_name = path.rsplit('/').next().unwrap_or(path);
    let extension = file_name.rsplit_once('.').map(|(_, extension)| extension);

    let documentation_only = path.starts_with("docs/")
        || matches!(extension, Some("md" | "mdx" | "rst"))
        || matches!(file_name, "readme" | "license" | "changelog");
    if documentation_only {
        needs.clear();
        needs.insert("documentation");
        return needs;
    }

    if is_dependency_path(path, file_name) {
        needs.extend(["dependencies", "operations"]);
    }
    if contains_any(
        path,
        &[
            "migration",
            "migrations/",
            "schema",
            "backfill",
            "seed",
            "database/",
            "db/",
        ],
    ) {
        needs.extend(["data-migrations", "operations", "privacy-compliance"]);
    }
    if contains_any(
        path,
        &[
            ".github/workflows/",
            "deploy",
            "docker",
            "infra/",
            "infrastructure/",
            "k8s/",
            "kubernetes/",
            "terraform/",
            "helm/",
            "ansible/",
            "nginx/",
            "runbook",
        ],
    ) {
        needs.extend(["dependencies", "operations", "observability"]);
    }
    if contains_any(
        path,
        &[
            "telemetry",
            "observability",
            "monitor",
            "metrics",
            "logging",
            "tracing",
            "alert",
        ],
    ) {
        needs.extend(["operations", "observability"]);
    }
    if contains_any(
        path,
        &[
            "bench",
            "performance",
            "load-test",
            "load_test",
            "query",
            "queries/",
            "assets/",
        ],
    ) {
        needs.insert("performance");
    }
    if contains_any(
        path,
        &[
            "ui/",
            "frontend/",
            "resources/views/",
            "templates/",
            "components/",
            "pages/",
            "public/",
            "accessibility",
            "a11y",
        ],
    ) || matches!(
        extension,
        Some("css" | "scss" | "sass" | "less" | "html" | "vue" | "svelte")
    ) {
        needs.extend(["product-ux", "performance"]);
    }
    if contains_any(
        path,
        &[
            "privacy",
            "personal-data",
            "personal_data",
            "payment",
            "billing",
            "moderation",
            "consent",
            "retention",
            "auth/",
            "identity/",
            "users/",
            "profiles/",
        ],
    ) {
        needs.insert("privacy-compliance");
    }
    if contains_any(
        path,
        &["security", "secret", "credential", "permission", "policy/"],
    ) {
        needs.insert("security");
    }

    needs
}

fn is_dependency_path(path: &str, file_name: &str) -> bool {
    matches!(
        file_name,
        "cargo.toml"
            | "cargo.lock"
            | "composer.json"
            | "composer.lock"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "requirements.txt"
            | "poetry.lock"
            | "pyproject.toml"
            | "go.mod"
            | "go.sum"
            | "gemfile"
            | "gemfile.lock"
    ) || path.starts_with(".github/dependabot")
}

fn contains_any(path: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| path.contains(needle))
}

fn sorted_strings<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut values: Vec<String> = values.into_iter().map(str::to_owned).collect();
    values.sort_unstable();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    fn needs(paths: &[&str]) -> Vec<String> {
        route_changed_paths(paths).review_needs
    }

    #[test]
    fn empty_and_documentation_routes_preserve_global_controls() {
        assert_eq!(needs(&[]), vec!["change-scope", "human-approval"]);
        assert_eq!(
            needs(&["docs/review.md"]),
            vec!["change-scope", "documentation", "human-approval"]
        );
    }

    #[test]
    fn matrix_covers_specialist_surfaces() {
        let cases = [
            (
                "src/service.rs",
                &["tests", "security", "documentation"][..],
            ),
            ("Cargo.lock", &["dependencies", "operations"][..]),
            (
                "database/migrations/001_users.sql",
                &["data-migrations", "privacy-compliance"][..],
            ),
            (
                "infra/prometheus/alerts.yml",
                &["operations", "observability"][..],
            ),
            ("benches/query.rs", &["performance"][..]),
            (
                "frontend/components/Profile.vue",
                &["product-ux", "performance"][..],
            ),
            ("src/payment/checkout.rs", &["privacy-compliance"][..]),
        ];

        for (path, expected) in cases {
            let routed = needs(&[path]);
            for review_need in expected {
                assert!(
                    routed.iter().any(|value| value == review_need),
                    "{path} did not route {review_need}"
                );
            }
        }
    }

    #[test]
    fn mixed_changes_produce_a_sorted_union() {
        let route = route_changed_paths([
            "Frontend\\Components\\Profile.vue",
            "database/migrations/001_users.sql",
            "Cargo.lock",
            "docs/review.md",
        ]);

        assert_eq!(
            route.changed_paths,
            vec![
                "cargo.lock",
                "database/migrations/001_users.sql",
                "docs/review.md",
                "frontend/components/profile.vue",
            ]
        );
        assert_eq!(
            route.review_needs,
            vec![
                "change-scope",
                "data-migrations",
                "dependencies",
                "documentation",
                "human-approval",
                "operations",
                "performance",
                "privacy-compliance",
                "product-ux",
                "security",
                "tests",
            ]
        );
    }

    #[test]
    fn routing_is_deterministic_and_deduplicated() {
        let first = route_changed_paths(["./SRC/lib.rs", "src\\lib.rs", "Cargo.toml"]);
        let second = route_changed_paths(["cargo.toml", "src/lib.rs"]);
        assert_eq!(first, second);
        assert!(
            first
                .path_applicability
                .iter()
                .all(|item| item.review_needs.windows(2).all(|pair| pair[0] < pair[1]))
        );
    }

    #[test]
    fn every_catalog_need_is_reachable() {
        let route = route_changed_paths([
            "src/service.rs",
            "Cargo.lock",
            "database/migrations/001_users.sql",
            "infra/observability/alerts.yml",
            "benches/query.rs",
            "frontend/components/Profile.vue",
        ]);
        assert_eq!(route.review_needs, sorted_strings(REVIEW_NEED_IDS));
    }
}
