use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};
use zero_review::{
    EvidenceStatus, Receipt, ReviewInput, adapter, apex_event_from_receipt, append_receipt,
    evaluate, inventory_repository, review_needs, review_needs_diagram, scan_security,
    verify_ledger,
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
        program: PathBuf,
        #[arg(long, default_value_t = 120_000)]
        timeout_ms: u64,
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
        out: Option<PathBuf>,
    },
    Doctor {
        #[arg(long, default_value = "http://127.0.0.1:8009/health")]
        apex_url: String,
    },
    LedgerAppend {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        evidence: Vec<String>,
    },
    LedgerVerify {
        #[arg(long)]
        ledger: PathBuf,
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
            emit(&evaluate(&parsed), out)
        }
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
            program,
            timeout_ms,
            args,
        } => emit(&adapter::run(&program, &args, timeout_ms).await?, None),
        Commands::SecurityScan { input, out } => {
            let contents = fs::read_to_string(&input)
                .with_context(|| format!("read security scan input {}", input.display()))?;
            emit(&scan_security(&contents), out)
        }
        Commands::ApexEvent { ledger, out } => {
            verify_ledger(&ledger)?;
            let contents = fs::read_to_string(&ledger)?;
            let line = contents
                .lines()
                .rfind(|line| !line.trim().is_empty())
                .context("receipt ledger is empty")?;
            let receipt: Receipt = serde_json::from_str(line)?;
            emit(&apex_event_from_receipt(&receipt)?, out)
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
            operation,
            subject,
            evidence,
        } => emit(
            &append_receipt(
                &ledger,
                &operation,
                &subject,
                EvidenceStatus::Verified,
                evidence,
            )?,
            None,
        ),
        Commands::LedgerVerify { ledger } => emit(
            &serde_json::json!({"entries":verify_ledger(&ledger)?,"chain":"valid"}),
            None,
        ),
    }
}
