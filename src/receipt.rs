use crate::model::{EvidenceStatus, Receipt};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

fn digest(
    timestamp: &str,
    operation: &str,
    subject: &str,
    status: &EvidenceStatus,
    evidence: &[String],
    previous: &str,
) -> String {
    let payload = serde_json::to_vec(&(timestamp, operation, subject, status, evidence, previous))
        .expect("serializable receipt fields");
    hex::encode(Sha256::digest(payload))
}

pub fn append_receipt(
    path: &Path,
    operation: &str,
    subject: &str,
    status: EvidenceStatus,
    evidence: Vec<String>,
) -> Result<Receipt> {
    let previous_hash = if path.exists() {
        fs::read_to_string(path)?
            .lines()
            .rfind(|line| !line.trim().is_empty())
            .map(serde_json::from_str::<Receipt>)
            .transpose()?
            .map(|r| r.hash)
            .unwrap_or_default()
    } else {
        String::new()
    };
    let timestamp = Utc::now().to_rfc3339();
    let hash = digest(
        &timestamp,
        operation,
        subject,
        &status,
        &evidence,
        &previous_hash,
    );
    let receipt = Receipt {
        timestamp,
        operation: operation.into(),
        subject: subject.into(),
        status,
        evidence,
        previous_hash,
        hash,
    };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open ledger {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(&receipt)?)?;
    Ok(receipt)
}

pub fn verify_ledger(path: &Path) -> Result<usize> {
    let content = fs::read_to_string(path)?;
    let mut previous = String::new();
    let mut count = 0;
    for (index, line) in content.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let receipt: Receipt = serde_json::from_str(line)
            .with_context(|| format!("invalid receipt at line {}", index + 1))?;
        if receipt.previous_hash != previous
            || receipt.hash
                != digest(
                    &receipt.timestamp,
                    &receipt.operation,
                    &receipt.subject,
                    &receipt.status,
                    &receipt.evidence,
                    &receipt.previous_hash,
                )
        {
            bail!("ledger chain invalid at line {}", index + 1);
        }
        previous = receipt.hash;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = directory.path().join("receipts.jsonl");
        append_receipt(
            &ledger,
            "inventory",
            "repo",
            EvidenceStatus::Verified,
            vec!["a".into()],
        )
        .unwrap();
        let changed = std::fs::read_to_string(&ledger)
            .unwrap()
            .replace("inventory", "invented");
        std::fs::write(&ledger, changed).unwrap();
        assert!(verify_ledger(&ledger).is_err());
    }
}
