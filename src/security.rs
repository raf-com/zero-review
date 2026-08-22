use crate::model::{EvidenceStatus, Finding, Severity};

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
    for (line_index, line) in contents.lines().enumerate() {
        let normalized = line.to_ascii_lowercase().replace(' ', "");
        for (id, needle, severity) in RULES {
            if normalized.contains(&needle.replace(' ', "")) {
                findings.push(Finding {
                    id: format!("security-{id}-{}", line_index + 1),
                    source: "zero-codereview.security.v1".into(),
                    severity: severity.clone(),
                    summary: format!(
                        "security-sensitive pattern {id} at input line {}",
                        line_index + 1
                    ),
                    evidence: vec![format!("line:{}", line_index + 1)],
                    status: EvidenceStatus::Verified,
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_key_material() {
        let findings = scan_security("+ -----BEGIN PRIVATE KEY-----");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn ignores_unrelated_diff() {
        assert!(scan_security("+ let total = price + tax;").is_empty());
    }
}
