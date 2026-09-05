use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::Duration};
use zero_review::{
    ApexProducerAssertion, Decision, Ed25519Keyring, EvidenceArtifact, EvidenceStatus,
    ExpectedOverride, ExpectedPullRequest, FileOverrideNonceStore, LedgerCheckpoint, Receipt,
    ReviewInput, ReviewOverride, ReviewPacket, ValidationContext, adapter,
    apex_event_from_receipt_authenticated, apex_producer_signing_payload, append_evidence_receipt,
    create_ledger_checkpoint, create_ledger_checkpoint_at, detect_drift, evaluate,
    inventory_ecosystem, inventory_repository, ledger_checkpoint_payload, review_needs,
    review_needs_diagram, scan_security, verify_ledger, verify_ledger_checkpoint,
    verify_ledger_evidence_with_root,
};

#[derive(Parser)]
#[command(
    name = "zero-review",
    about = "Evidence-first code-review control plane"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Inventory {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Evaluate {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Ecosystem {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        diagram: PathBuf,
    },
    EcosystemDrift {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long, default_value_t = 86_400)]
        max_age_seconds: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Route {
        #[arg(long)]
        path: Vec<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Diagram {
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Needs {
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        diagram: Option<PathBuf>,
    },
    Adapter {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        adapter_id: String,
        #[arg(last = true)]
        args: Vec<String>,
    },
    SecurityScan {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    ApexEvent {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        evidence_root: PathBuf,
        #[arg(long)]
        release_artifact: PathBuf,
        #[arg(long)]
        keyring: PathBuf,
        #[arg(long)]
        producer_id: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        signature: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    ApexSigningPayload {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        evidence_root: PathBuf,
        #[arg(long)]
        release_artifact: PathBuf,
        #[arg(long)]
        producer_id: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    ValidateReviewPacket {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        repository: String,
        #[arg(long)]
        pull_request_number: u64,
        #[arg(long)]
        base_sha: String,
        #[arg(long)]
        head_sha: String,
        #[arg(long, default_value_t = 3600)]
        maximum_age_seconds: i64,
    },
    ValidateOverride {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        repository: String,
        #[arg(long)]
        pull_request_number: u64,
        #[arg(long)]
        base_sha: String,
        #[arg(long)]
        head_sha: String,
        #[arg(long)]
        tool_release_digest: String,
        #[arg(long)]
        keyring: PathBuf,
        #[arg(long)]
        nonce_store: PathBuf,
        #[arg(long, default_value_t = 14_400)]
        maximum_duration_seconds: i64,
    },
    Doctor {
        #[arg(long, default_value = "http://127.0.0.1:8009/health")]
        apex_url: String,
    },
    LedgerAppend {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        evidence_root: PathBuf,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        evidence: Vec<String>,
        #[arg(long, default_value = "not_proven")]
        status: String,
    },
    LedgerVerify {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        strict_evidence: bool,
        #[arg(long, requires = "strict_evidence")]
        evidence_root: Option<PathBuf>,
    },
    LedgerCheckpointPayload {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        ledger_id: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    LedgerCheckpointCreate {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        ledger_id: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        created_at: chrono::DateTime<Utc>,
        #[arg(long)]
        signature: String,
        #[arg(long)]
        out: PathBuf,
    },
    LedgerCheckpointVerify {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        keyring: PathBuf,
    },
}

fn emit<T: serde::Serialize>(value: &T, out: Option<PathBuf>) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    if let Some(path) = out {
        fs::write(&path, format!("{json}\n"))
            .with_context(|| format!("write {}", path.display()))?;
    } else {
        println!("{json}");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Inventory { repo, out } => emit(&inventory_repository(&repo)?, out),
        Commands::Evaluate { input, out } => {
            let parsed: ReviewInput = serde_json::from_slice(&fs::read(&input)?)?;
            if parsed.schema_version != "zero-review.findings.v1" {
                anyhow::bail!(
                    "unsupported schema_version {}; expected zero-review.findings.v1",
                    parsed.schema_version
                );
            }
            let decision = evaluate(&parsed);
            emit(&decision, out)?;
            match decision.decision {
                Decision::Pass => Ok(()),
                Decision::NeedsReview => anyhow::bail!("review requires additional evidence"),
                Decision::Block => anyhow::bail!("review is blocked"),
            }
        }
        Commands::Ecosystem {
            config,
            out,
            diagram,
        } => {
            let inventory = zero_review::inventory_ecosystem(&config)?;
            fs::write(&diagram, zero_review::render_ecosystem_diagram(&inventory))?;
            emit(&inventory, Some(out))
        }
        Commands::EcosystemDrift {
            config,
            snapshot,
            max_age_seconds,
            out,
        } => {
            let baseline: zero_review::EcosystemInventory =
                serde_json::from_slice(&fs::read(&snapshot)?)?;
            let current = inventory_ecosystem(&config)?;
            let drift = detect_drift(
                &baseline,
                &current,
                Utc::now(),
                Duration::from_secs(max_age_seconds),
            )?;
            emit(&drift, out)?;
            if drift.is_clean() {
                Ok(())
            } else {
                anyhow::bail!("ecosystem snapshot drift detected")
            }
        }
        Commands::Route { path, out } => emit(&zero_review::route_changed_paths(path), out),
        Commands::Diagram { inventory, out } => {
            let inv: zero_review::Inventory = serde_json::from_slice(&fs::read(&inventory)?)?;
            let mut graph = String::from(
                "flowchart LR\n  PR[Pull Request] --> INV[Control inventory]\n  INV --> NATIVE[zero-pr-review / zero-lint]\n  NATIVE --> JUDGE[Normalized findings]\n  JUDGE --> POLICY[zero-review policy]\n  POLICY --> PROOF[zero-proof / oracle]\n  PROOF --> APEX[Apex advisory trace]\n  POLICY --> RECEIPT[Hash-chained receipt]\n",
            );
            for (i, control) in inv.controls.iter().enumerate() {
                graph.push_str(&format!(
                    "  INV --> C{}[\"{}: {}\"]\n",
                    i,
                    control.kind,
                    control.path.replace('"', "'")
                ));
            }
            fs::write(out, graph)?;
            Ok(())
        }
        Commands::Needs { out, diagram } => {
            emit(&review_needs(), out)?;
            if let Some(path) = diagram {
                fs::write(path, review_needs_diagram())?;
            }
            Ok(())
        }
        Commands::Adapter {
            registry,
            adapter_id,
            args,
        } => emit(
            &adapter::run_registered_file(&registry, &adapter_id, &args).await?,
            None,
        ),
        Commands::SecurityScan { input, out } => {
            let contents = fs::read_to_string(&input)
                .with_context(|| format!("read security scan input {}", input.display()))?;
            emit(&scan_security(&contents), out)
        }
        Commands::ApexEvent {
            ledger,
            evidence_root,
            release_artifact,
            keyring,
            producer_id,
            key_id,
            signature,
            out,
        } => {
            verify_ledger_evidence_with_root(&ledger, &evidence_root)?;
            let contents = fs::read_to_string(&ledger)?;
            let line = contents
                .lines()
                .rfind(|line| !line.trim().is_empty())
                .context("receipt ledger is empty")?;
            let receipt: Receipt = serde_json::from_str(line)?;
            let producer = ApexProducerAssertion {
                producer_id,
                key_id,
                signature,
            };
            let verifier = Ed25519Keyring::load(&keyring)?;
            emit(
                &apex_event_from_receipt_authenticated(
                    &receipt,
                    &release_artifact,
                    &producer,
                    &verifier,
                )?,
                out,
            )
        }
        Commands::ApexSigningPayload {
            ledger,
            evidence_root,
            release_artifact,
            producer_id,
            key_id,
            out,
        } => {
            verify_ledger_evidence_with_root(&ledger, &evidence_root)?;
            let contents = fs::read_to_string(&ledger)?;
            let line = contents
                .lines()
                .rfind(|line| !line.trim().is_empty())
                .context("receipt ledger is empty")?;
            let receipt: Receipt = serde_json::from_str(line)?;
            let payload =
                apex_producer_signing_payload(&receipt, &release_artifact, &producer_id, &key_id)?;
            emit(
                &serde_json::json!({
                    "schema_version": "zero-review.apex-signing-payload.v1",
                    "payload_hex": hex::encode(&payload),
                    "payload_sha256": format!("sha256:{}", hex::encode(Sha256::digest(&payload)))
                }),
                out,
            )
        }
        Commands::ValidateReviewPacket {
            input,
            repository,
            pull_request_number,
            base_sha,
            head_sha,
            maximum_age_seconds,
        } => {
            let bytes = fs::read(input)?;
            require_current_schema(
                &bytes,
                "zero-review.review-packet.v3",
                &[
                    "zero-review.review-packet.v1",
                    "zero-review.review-packet.v2",
                ],
            )?;
            let packet: ReviewPacket = serde_json::from_slice(&bytes)?;
            let validation = ValidationContext {
                expected_head_sha: &head_sha,
                now: Utc::now(),
                maximum_context_age: chrono::Duration::seconds(maximum_age_seconds),
                maximum_review_age: chrono::Duration::seconds(maximum_age_seconds),
                maximum_override_duration: chrono::Duration::zero(),
            };
            packet.validate_bound(
                &validation,
                &ExpectedPullRequest {
                    repository: &repository,
                    pull_request_number,
                    base_sha: &base_sha,
                    head_sha: &head_sha,
                },
            )?;
            emit(&serde_json::json!({"status":"verified"}), None)
        }
        Commands::ValidateOverride {
            input,
            repository,
            pull_request_number,
            base_sha,
            head_sha,
            tool_release_digest,
            keyring,
            nonce_store,
            maximum_duration_seconds,
        } => {
            let bytes = fs::read(input)?;
            require_current_schema(
                &bytes,
                "zero-review.override.v2",
                &["zero-review.override.v1"],
            )?;
            let review_override: ReviewOverride = serde_json::from_slice(&bytes)?;
            let validation = ValidationContext {
                expected_head_sha: &head_sha,
                now: Utc::now(),
                maximum_context_age: chrono::Duration::zero(),
                maximum_review_age: chrono::Duration::zero(),
                maximum_override_duration: chrono::Duration::seconds(maximum_duration_seconds),
            };
            let verifier = Ed25519Keyring::load(&keyring)?;
            let mut nonces = FileOverrideNonceStore::new(nonce_store);
            review_override.validate_bound(
                &validation,
                &ExpectedOverride {
                    pull_request: ExpectedPullRequest {
                        repository: &repository,
                        pull_request_number,
                        base_sha: &base_sha,
                        head_sha: &head_sha,
                    },
                    tool_release_digest: &tool_release_digest,
                },
            )?;
            review_override.validate_authenticated(&validation, &verifier, &mut nonces)?;
            emit(&serde_json::json!({"status":"verified"}), None)
        }
        Commands::Doctor { apex_url } => match adapter::probe(&apex_url).await {
            Ok(v) => emit(&v, None),
            Err(e) => emit(
                &serde_json::json!({"url":apex_url,"reachable":false,"error":e.to_string()}),
                None,
            ),
        },
        Commands::LedgerAppend {
            ledger,
            evidence_root,
            operation,
            subject,
            evidence,
            status,
        } => emit(
            &append_evidence_receipt(
                &ledger,
                &operation,
                &subject,
                parse_status(&status)?,
                evidence
                    .iter()
                    .map(|path| {
                        EvidenceArtifact::store_file(
                            "review_artifact",
                            PathBuf::from(path).as_path(),
                            &evidence_root,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?,
            )?,
            None,
        ),
        Commands::LedgerVerify {
            ledger,
            strict_evidence,
            evidence_root,
        } => {
            let entries = if strict_evidence {
                verify_ledger_evidence_with_root(
                    &ledger,
                    evidence_root
                        .as_deref()
                        .context("--evidence-root is required")?,
                )?
            } else {
                verify_ledger(&ledger)?
            };
            emit(
                &serde_json::json!({
                    "entries": entries,
                    "chain": "valid",
                    "evidence": if strict_evidence { "verified" } else { "not_checked" }
                }),
                None,
            )
        }
        Commands::LedgerCheckpointPayload {
            ledger,
            ledger_id,
            key_id,
            out,
        } => {
            let checkpoint =
                create_ledger_checkpoint(&ledger, &ledger_id, &key_id, "0".repeat(128))?;
            let payload = ledger_checkpoint_payload(
                &ledger_id,
                checkpoint.entry_count,
                &checkpoint.last_entry_hash,
                &key_id,
                checkpoint.created_at,
            )?;
            emit(
                &serde_json::json!({
                    "schema_version": "zero-review.ledger-checkpoint-signing-payload.v1",
                    "entry_count": checkpoint.entry_count,
                    "last_entry_hash": checkpoint.last_entry_hash,
                    "payload_hex": hex::encode(&payload),
                    "payload_sha256": format!("sha256:{}", hex::encode(Sha256::digest(&payload)))
                }),
                out,
            )
        }
        Commands::LedgerCheckpointCreate {
            ledger,
            ledger_id,
            key_id,
            created_at,
            signature,
            out,
        } => emit(
            &create_ledger_checkpoint_at(&ledger, ledger_id, key_id, created_at, signature)?,
            Some(out),
        ),
        Commands::LedgerCheckpointVerify {
            ledger,
            checkpoint,
            keyring,
        } => {
            let checkpoint: LedgerCheckpoint = serde_json::from_slice(&fs::read(checkpoint)?)?;
            let verifier = Ed25519Keyring::load(&keyring)?;
            let entries = verify_ledger_checkpoint(&ledger, &checkpoint, &verifier)?;
            emit(
                &serde_json::json!({"status":"verified","entries":entries}),
                None,
            )
        }
    }
}

fn parse_status(value: &str) -> Result<EvidenceStatus> {
    match value {
        "verified" => Ok(EvidenceStatus::Verified),
        "partial" => Ok(EvidenceStatus::Partial),
        "blocked" => Ok(EvidenceStatus::Blocked),
        "owner_gated" => Ok(EvidenceStatus::OwnerGated),
        "not_proven" => Ok(EvidenceStatus::NotProven),
        _ => anyhow::bail!("unsupported evidence status: {value}"),
    }
}

fn require_current_schema(bytes: &[u8], expected: &str, legacy: &[&str]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let actual = value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .context("schema_version is required")?;
    if legacy.contains(&actual) {
        anyhow::bail!(
            "{actual} is recognized for archived decoding but lacks current execution provenance; migrate to {expected}"
        );
    }
    if actual != expected {
        anyhow::bail!("unsupported schema_version {actual}; expected {expected}");
    }
    Ok(())
}
