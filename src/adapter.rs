use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{path::Path, process::Stdio};
use tokio::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct AdapterResult {
    pub program: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub async fn run(program: &Path, args: &[String], timeout_ms: u64) -> Result<AdapterResult> {
    if !program.is_file() {
        bail!("adapter executable not found: {}", program.display());
    }
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null()).kill_on_drop(true);
    let output = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        command.output(),
    )
    .await
    .with_context(|| {
        format!(
            "adapter timed out after {timeout_ms}ms: {}",
            program.display()
        )
    })?
    .with_context(|| format!("run adapter {}", program.display()))?;
    Ok(AdapterResult {
        program: program.display().to_string(),
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into(),
        stderr: String::from_utf8_lossy(&output.stderr).into(),
    })
}

pub async fn probe(url: &str) -> Result<serde_json::Value> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let response = client.get(url).send().await?;
    Ok(
        serde_json::json!({"url":url,"status":response.status().as_u16(),"reachable":response.status().is_success()}),
    )
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_adapter_reports_timeout() {
        let arguments = vec![
            "-NoProfile".into(),
            "-Command".into(),
            "Start-Sleep -Seconds 5".into(),
        ];
        let error = run(
            Path::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            &arguments,
            25,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }
}
