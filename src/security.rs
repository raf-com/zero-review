use crate::model::{EvidenceStatus, Finding, Severity};
use sha2::{Digest, Sha256};

const RULES: &[(&str, &str, Severity)] = &[
    (
        "private-key",
        "-----begin private key-----",
        Severity::Block,
    ),
    ("aws-access-key", "akia", Severity::Block),
    ("php-eval", "eval(", Severity::Warning),
    ("php-shell-exec", "shell_exec(", Severity::Warning),
    ("node-child-process", "child_process", Severity::Warning),
    (
        "disabled-tls-verification",
        "rejectunauthorized:false",
        Severity::Block,
    ),
];

pub fn scan_security(contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut in_hunk = false;
    for (line_index, line) in contents.lines().enumerate() {
        if line.starts_with("diff --git ") || line.starts_with("--- ") {
            in_hunk = false;
            continue;
        }
        if line.starts_with("@@ ") {
            in_hunk = true;
            continue;
        }
        let Some(added_line) = added_content(line, in_hunk) else {
            continue;
        };
        let normalized = added_line.to_ascii_lowercase().replace(' ', "");
        for (id, needle, severity) in RULES {
            if normalized.contains(&needle.replace(' ', "")) {
                let digest = hex::encode(Sha256::digest(added_line.as_bytes()));
                findings.push(Finding {
                    id: format!("security-{id}-{}", line_index + 1),
                    source: "zero-review.security.v1".into(),
                    severity: severity.clone(),
                    summary: format!(
                        "security-sensitive pattern {id} at input line {}",
                        line_index + 1
                    ),
                    evidence: vec![
                        format!("unified-diff-line:{}", line_index + 1),
                        format!("sha256:{digest}"),
                    ],
                    status: EvidenceStatus::Verified,
                });
            }
        }
    }
    findings.push(Finding {
        id: "security-specialist-adapters-unavailable".into(),
        source: "zero-review.security.specialists.v1".into(),
        severity: Severity::Warning,
        summary:
            "specialist security adapters were not supplied; built-in pattern coverage is partial"
                .into(),
        evidence: vec!["scanner:zero-review.security.v1".into()],
        status: EvidenceStatus::NotProven,
    });
    findings
}

fn added_content(line: &str, in_hunk: bool) -> Option<&str> {
    in_hunk.then(|| line.strip_prefix('+')).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_key_material_on_added_line() {
        let findings = scan_security(
            "diff --git a/key.pem b/key.pem\n--- a/key.pem\n+++ b/key.pem\n@@ -0,0 +1 @@\n+ -----BEGIN PRIVATE KEY-----",
        );
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Block);
        assert_eq!(findings[0].status, EvidenceStatus::Verified);
        assert!(findings[0].evidence[0].starts_with("unified-diff-line:"));
        assert!(findings[0].evidence[1].starts_with("sha256:"));
    }

    #[test]
    fn clean_diff_reports_specialist_coverage_as_not_proven() {
        let findings = scan_security("@@ -1 +1 @@\n+ let total = price + tax;");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, EvidenceStatus::NotProven);
        assert_eq!(findings[0].id, "security-specialist-adapters-unavailable");
    }

    #[test]
    fn ignores_removed_context_and_file_header_lines() {
        let findings = scan_security(
            "--- a/example.pem\n+++ b/example.pem\n- -----BEGIN PRIVATE KEY-----\n context eval(",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security-specialist-adapters-unavailable");
    }

    #[test]
    fn scans_only_added_side_of_a_unified_diff() {
        let findings = scan_security("@@ -1,2 +1,2 @@\n- eval($old);\n+ shell_exec($request);");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].id, "security-php-shell-exec-3");
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn scans_added_content_that_begins_with_two_plus_characters() {
        let findings = scan_security("@@ -0,0 +1 @@\n+++eval(user_input)");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].id, "security-php-eval-2");
    }
}
