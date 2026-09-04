use crate::model::{Decision, EvidenceStatus, ReviewDecision, ReviewInput, Severity};

pub fn evaluate(input: &ReviewInput) -> ReviewDecision {
    let blocking_count = input
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Block)
        .count();
    let finding_unproven_count = input
        .findings
        .iter()
        .filter(|f| {
            f.status != EvidenceStatus::Verified
                || f.evidence.is_empty()
                || f.evidence.iter().any(|e| !valid_evidence_digest(e))
        })
        .count();
    let missing_controls: Vec<String> = input
        .required_controls
        .iter()
        .filter(|control| {
            !input
                .findings
                .iter()
                .any(|finding| finding.source.eq_ignore_ascii_case(control))
        })
        .cloned()
        .collect();
    let unproven_count = finding_unproven_count + missing_controls.len();
    let mut reasons = Vec::new();
    let decision = if blocking_count > 0 {
        reasons.push(format!("{blocking_count} blocking finding(s)"));
        Decision::Block
    } else if !missing_controls.is_empty() {
        reasons.push(format!(
            "required controls have no supplied result: {}",
            missing_controls.join(", ")
        ));
        Decision::NeedsReview
    } else if unproven_count > 0 {
        reasons.push(format!(
            "{unproven_count} finding(s) lack verified evidence"
        ));
        Decision::NeedsReview
    } else {
        reasons.push("all supplied findings are verified and non-blocking".into());
        Decision::Pass
    };
    ReviewDecision {
        decision,
        reasons,
        missing_controls,
        finding_count: input.findings.len(),
        blocking_count,
        unproven_count,
    }
}

fn valid_evidence_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;
    use std::path::PathBuf;

    fn input(severity: Severity, status: EvidenceStatus) -> ReviewInput {
        ReviewInput {
            schema_version: "zero-review.findings.v1".into(),
            repository: PathBuf::from("repo"),
            required_controls: vec![],
            findings: vec![Finding {
                id: "x".into(),
                source: "test".into(),
                severity,
                summary: "x".into(),
                evidence: vec![format!("sha256:{}", "a".repeat(64))],
                status,
            }],
        }
    }
    #[test]
    fn blocks_blocking_findings() {
        assert_eq!(
            evaluate(&input(Severity::Block, EvidenceStatus::Verified)).decision,
            Decision::Block
        );
    }
    #[test]
    fn routes_unproven_to_review() {
        assert_eq!(
            evaluate(&input(Severity::Warning, EvidenceStatus::NotProven)).decision,
            Decision::NeedsReview
        );
    }
    #[test]
    fn passes_verified_advisory() {
        assert_eq!(
            evaluate(&input(Severity::Warning, EvidenceStatus::Verified)).decision,
            Decision::Pass
        );
    }

    #[test]
    fn missing_required_control_needs_review() {
        let mut review = input(Severity::Warning, EvidenceStatus::Verified);
        review.required_controls = vec!["security".into()];
        assert_eq!(evaluate(&review).decision, Decision::NeedsReview);
        assert_eq!(evaluate(&review).missing_controls, vec!["security"]);
    }
}
