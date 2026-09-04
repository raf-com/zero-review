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
        .filter(|f| f.status != EvidenceStatus::Verified)
        .count();
    let missing_controls: Vec<String> = input
        .required_controls
        .iter()
        .filter(|control| {
            !input.findings.iter().any(|finding| {
                finding.source.eq_ignore_ascii_case(control)
                    || finding
                        .source
                        .to_ascii_lowercase()
                        .contains(&control.to_ascii_lowercase())
            })
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
                evidence: vec![],
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
