use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::process::Command;

const SCHEMA: &str = "zero-review.adapter-registry.v1";
const MAX_TIMEOUT_MS: u64 = 900_000;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterRegistry {
    pub schema_version: String,
    pub adapters: Vec<AdapterConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    pub id: String,
    pub executable: PathBuf,
    pub sha256: String,
    #[serde(default)]
    pub allowed_arguments: Vec<String>,
    pub working_directory: PathBuf,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    pub timeout_ms: u64,
    pub output_limit_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdapterResult {
    pub program: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

pub fn load_registry(path: &Path) -> Result<AdapterRegistry> {
    let bytes =
        fs::read(path).with_context(|| format!("read adapter registry {}", path.display()))?;
    let registry: AdapterRegistry = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse adapter registry {}", path.display()))?;
    validate_registry(&registry)?;
    Ok(registry)
}

pub fn validate_registry(registry: &AdapterRegistry) -> Result<()> {
    if registry.schema_version != SCHEMA {
        bail!(
            "unsupported adapter registry schema: {}",
            registry.schema_version
        );
    }
    let mut ids = BTreeSet::new();
    for adapter in &registry.adapters {
        if adapter.id.trim().is_empty() || !ids.insert(adapter.id.as_str()) {
            bail!("adapter id must be non-empty and unique: {}", adapter.id);
        }
        if !adapter.executable.is_absolute() || !adapter.working_directory.is_absolute() {
            bail!(
                "adapter {} executable and working directory must be absolute",
                adapter.id
            );
        }
        if adapter.sha256.len() != 64
            || !adapter
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            bail!("adapter {} requires a lowercase SHA-256 digest", adapter.id);
        }
        if adapter.timeout_ms == 0 || adapter.timeout_ms > MAX_TIMEOUT_MS {
            bail!(
                "adapter {} timeout is outside the allowed range",
                adapter.id
            );
        }
        if adapter.output_limit_bytes == 0 || adapter.output_limit_bytes > MAX_OUTPUT_BYTES {
            bail!(
                "adapter {} output limit is outside the allowed range",
                adapter.id
            );
        }
        if adapter.allowed_arguments.iter().any(String::is_empty) {
            bail!("adapter {} has an empty argument prefix", adapter.id);
        }
        if adapter.environment.keys().any(|key| {
            key.is_empty()
                || key.contains('=')
                || key.contains('\0')
                || key.eq_ignore_ascii_case("PATH")
                || key.eq_ignore_ascii_case("PATHEXT")
        }) {
            bail!(
                "adapter {} has an invalid process environment key",
                adapter.id
            );
        }
    }
    Ok(())
}

/// Compatibility entrypoint: requires an explicit registry via environment and
/// matches the requested executable and timeout against it.
pub async fn run(program: &Path, args: &[String], timeout_ms: u64) -> Result<AdapterResult> {
    let registry_path = std::env::var_os("ZERO_REVIEW_ADAPTER_REGISTRY")
        .map(PathBuf::from)
        .context("ZERO_REVIEW_ADAPTER_REGISTRY is required")?;
    let registry = load_registry(&registry_path)?;
    let requested =
        fs::canonicalize(program).with_context(|| format!("canonicalize {}", program.display()))?;
    let adapter = registry
        .adapters
        .iter()
        .find(|entry| fs::canonicalize(&entry.executable).ok().as_ref() == Some(&requested))
        .with_context(|| {
            format!(
                "adapter executable is not registered: {}",
                program.display()
            )
        })?;
    if timeout_ms != adapter.timeout_ms {
        bail!(
            "adapter timeout must match configured value {}ms",
            adapter.timeout_ms
        );
    }
    run_configured(adapter, args).await
}

pub async fn run_registered(
    registry: &AdapterRegistry,
    adapter_id: &str,
    args: &[String],
) -> Result<AdapterResult> {
    validate_registry(registry)?;
    let adapter = registry
        .adapters
        .iter()
        .find(|entry| entry.id == adapter_id)
        .with_context(|| format!("adapter is not registered: {adapter_id}"))?;
    run_configured(adapter, args).await
}

/// Registry-first entrypoint for CLI and orchestration callers. The caller never
/// supplies an executable path or timeout, only a reviewed adapter identifier.
pub async fn run_registered_file(
    registry_path: &Path,
    adapter_id: &str,
    args: &[String],
) -> Result<AdapterResult> {
    let registry = load_registry(registry_path)?;
    run_registered(&registry, adapter_id, args).await
}

async fn run_configured(adapter: &AdapterConfig, args: &[String]) -> Result<AdapterResult> {
    validate_arguments(adapter, args)?;
    if !adapter.executable.is_file() {
        bail!(
            "adapter executable not found: {}",
            adapter.executable.display()
        );
    }
    reject_reparse_point(&adapter.executable)?;
    if !adapter.working_directory.is_dir() {
        bail!(
            "adapter working directory not found: {}",
            adapter.working_directory.display()
        );
    }
    let execution = PrivateExecution::prepare(adapter)?;
    let actual = sha256_file(&execution.executable)?;
    if actual != adapter.sha256 {
        bail!(
            "adapter executable digest mismatch for {}: expected {}, got {}",
            adapter.id,
            adapter.sha256,
            actual
        );
    }
    let stdout_path = execution.directory.join("stdout");
    let stderr_path = execution.directory.join("stderr");
    let stdout_file = create_output(&stdout_path)?;
    let stderr_file = create_output(&stderr_path)?;
    let result = async {
        let mut command = Command::new(&execution.executable);
        configure_process_tree(&mut command);
        let mut child = command
            .args(args)
            .current_dir(&adapter.working_directory)
            .env_clear()
            .envs(&adapter.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("run configured adapter {}", adapter.id))?;
        let status =
            match tokio::time::timeout(Duration::from_millis(adapter.timeout_ms), child.wait())
                .await
            {
                Ok(status) => status.with_context(|| format!("wait for adapter {}", adapter.id))?,
                Err(_) => {
                    terminate_process_tree(&mut child).await.with_context(|| {
                        format!("kill timed out adapter process tree {}", adapter.id)
                    })?;
                    let _ = child.wait().await;
                    bail!(
                        "adapter timed out after {}ms: {}",
                        adapter.timeout_ms,
                        adapter.id
                    );
                }
            };
        let (stdout, stdout_truncated) = read_bounded(&stdout_path, adapter.output_limit_bytes)?;
        let (stderr, stderr_truncated) = read_bounded(&stderr_path, adapter.output_limit_bytes)?;
        Ok(AdapterResult {
            program: adapter.executable.display().to_string(),
            success: status.success(),
            exit_code: status.code(),
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
        })
    }
    .await;
    let cleanup = execution.close();
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(run_error), Ok(())) => Err(run_error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(run_error), Err(cleanup_error)) => Err(run_error.context(cleanup_error)),
    }
}

#[cfg(windows)]
fn reject_reparse_point(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let attributes = fs::symlink_metadata(path)?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!(
            "adapter executable must not be a Windows reparse point: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_reparse_point(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!(
            "adapter executable must not be a symbolic link: {}",
            path.display()
        );
    }
    Ok(())
}

/// A private execution workspace closes the digest-check/exec race: the configured
/// source is copied first, the copy is verified, and only that copy is executed.
/// Explicit `close` reports cleanup failures; `Drop` remains a best-effort fallback.
struct PrivateExecution {
    directory: PathBuf,
    executable: PathBuf,
    closed: bool,
}

impl PrivateExecution {
    fn prepare(adapter: &AdapterConfig) -> Result<Self> {
        let directory = private_directory(&adapter.id)?;
        let extension = adapter.executable.extension().and_then(|v| v.to_str());
        let name = extension.map_or_else(|| "adapter".to_owned(), |ext| format!("adapter.{ext}"));
        let executable = directory.join(name);
        let prepared = (|| {
            fs::copy(&adapter.executable, &executable).with_context(|| {
                format!(
                    "copy adapter {} into private execution workspace",
                    adapter.id
                )
            })?;
            restrict_file(&executable)?;
            Ok(Self {
                directory: directory.clone(),
                executable,
                closed: false,
            })
        })();
        if prepared.is_err() {
            let _ = fs::remove_dir_all(&directory);
        }
        prepared
    }

    fn close(mut self) -> Result<()> {
        fs::remove_dir_all(&self.directory).with_context(|| {
            format!(
                "remove private adapter workspace {}",
                self.directory.display()
            )
        })?;
        self.closed = true;
        Ok(())
    }
}

impl Drop for PrivateExecution {
    fn drop(&mut self) {
        if !self.closed {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}

fn validate_arguments(adapter: &AdapterConfig, args: &[String]) -> Result<()> {
    for argument in args {
        if argument.contains('\0')
            || !adapter
                .allowed_arguments
                .iter()
                .any(|allowed| argument == allowed)
        {
            bail!(
                "argument is not allowed for adapter {}: {argument:?}",
                adapter.id
            );
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn private_directory(id: &str) -> Result<PathBuf> {
    let safe_id: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let path = tempfile::Builder::new()
        .prefix(&format!("zero-review-{safe_id}-"))
        .tempdir()?
        .keep();
    restrict_directory(&path)?;
    Ok(path)
}

fn create_output(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create adapter output {}", path.display()))?;
    restrict_file(path)?;
    Ok(file)
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn restrict_directory(path: &Path) -> Result<()> {
    let identity = windows_identity()?;
    let status = std::process::Command::new("C:\\Windows\\System32\\icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("{identity}:(OI)(CI)F"))
        .arg("SYSTEM:(OI)(CI)F")
        .status()
        .context("apply private adapter workspace DACL")?;
    if !status.success() {
        bail!("failed to apply private adapter workspace DACL");
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn restrict_file(path: &Path) -> Result<()> {
    reject_reparse_point(path)?;
    Ok(())
}

#[cfg(windows)]
fn windows_identity() -> Result<String> {
    let user = std::env::var("USERNAME").context("USERNAME is required for adapter DACL")?;
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    Ok(if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    })
}

#[cfg(unix)]
fn configure_process_tree(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.as_std_mut().process_group(0);
}

#[cfg(windows)]
fn configure_process_tree(_command: &mut Command) {}

#[cfg(unix)]
async fn terminate_process_tree(child: &mut tokio::process::Child) -> Result<()> {
    if let Some(pid) = child.id() {
        let status = Command::new("kill")
            .args(["-KILL", &format!("-{pid}")])
            .status()
            .await?;
        if !status.success() {
            child.kill().await?;
        }
    }
    Ok(())
}

#[cfg(windows)]
async fn terminate_process_tree(child: &mut tokio::process::Child) -> Result<()> {
    if let Some(pid) = child.id() {
        let status = Command::new("C:\\Windows\\System32\\taskkill.exe")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status()
            .await?;
        if !status.success() {
            child.kill().await?;
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: usize) -> Result<(String, bool)> {
    let mut bytes = Vec::with_capacity(limit.min(65_536));
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    Ok((String::from_utf8_lossy(&bytes).into_owned(), truncated))
}

pub async fn probe(url: &str) -> Result<serde_json::Value> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let response = client.get(url).send().await?;
    Ok(
        serde_json::json!({"url":url,"status":response.status().as_u16(),"reachable":response.status().is_success()}),
    )
}

#[cfg(test)]
mod portable_tests {
    use super::*;

    fn registry() -> AdapterRegistry {
        AdapterRegistry {
            schema_version: SCHEMA.into(),
            adapters: vec![AdapterConfig {
                id: "portable".into(),
                executable: if cfg!(windows) {
                    PathBuf::from(r"C:\adapter.exe")
                } else {
                    PathBuf::from("/adapter")
                },
                sha256: "a".repeat(64),
                allowed_arguments: vec!["--check".into()],
                working_directory: if cfg!(windows) {
                    PathBuf::from(r"C:\work")
                } else {
                    PathBuf::from("/work")
                },
                environment: BTreeMap::new(),
                timeout_ms: 1_000,
                output_limit_bytes: 1_024,
            }],
        }
    }

    #[test]
    fn validation_accepts_a_portable_well_formed_registry() {
        validate_registry(&registry()).unwrap();
    }

    #[test]
    fn validation_rejects_duplicates_uppercase_digest_and_path_environment() {
        let mut value = registry();
        value.adapters.push(value.adapters[0].clone());
        assert!(validate_registry(&value).is_err());
        value = registry();
        value.adapters[0].sha256 = "A".repeat(64);
        assert!(validate_registry(&value).is_err());
        value = registry();
        value.adapters[0]
            .environment
            .insert("PATH".into(), "unsafe".into());
        assert!(validate_registry(&value).is_err());
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use tempfile::TempDir;
    fn config(temp: &TempDir, timeout_ms: u64, output_limit_bytes: usize) -> AdapterConfig {
        let executable = PathBuf::from("C:\\Windows\\System32\\cmd.exe");
        AdapterConfig {
            id: "powershell-test".into(),
            sha256: sha256_file(&executable).unwrap(),
            executable,
            allowed_arguments: vec![
                "/d".into(),
                "/c".into(),
                "echo 123456789".into(),
                "C:\\Windows\\System32\\ping.exe -n 6 127.0.0.1 >nul".into(),
            ],
            working_directory: temp.path().to_path_buf(),
            environment: BTreeMap::from([(
                "SystemRoot".into(),
                std::env::var("SystemRoot").expect("Windows supplies SystemRoot"),
            )]),
            timeout_ms,
            output_limit_bytes,
        }
    }
    #[tokio::test]
    async fn digest_pinned_execution_bounds_output() {
        let temp = TempDir::new().unwrap();
        let cfg = config(&temp, 30_000, 4);
        let registry = AdapterRegistry {
            schema_version: SCHEMA.into(),
            adapters: vec![cfg],
        };
        let result = run_registered(
            &registry,
            "powershell-test",
            &["/d".into(), "/c".into(), "echo 123456789".into()],
        )
        .await
        .unwrap();
        assert!(result.success && result.stdout_truncated);
        assert_eq!(result.stdout.len(), 4);
    }
    #[tokio::test]
    async fn rejects_unlisted_arguments_and_digest_drift() {
        let temp = TempDir::new().unwrap();
        let mut cfg = config(&temp, 5_000, 100);
        assert!(
            run_configured(&cfg, &["/q".into()])
                .await
                .unwrap_err()
                .to_string()
                .contains("not allowed")
        );
        cfg.sha256 = "0".repeat(64);
        assert!(
            run_configured(&cfg, &[])
                .await
                .unwrap_err()
                .to_string()
                .contains("digest mismatch")
        );
    }
    #[tokio::test]
    async fn rejects_shell_text_appended_to_allowed_argument() {
        let temp = TempDir::new().unwrap();
        let cfg = config(&temp, 5_000, 100);
        let error = run_configured(
            &cfg,
            &["/d".into(), "/c".into(), "echo 123456789 & set".into()],
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("not allowed"));
    }
    #[tokio::test]
    async fn kills_on_timeout() {
        let temp = TempDir::new().unwrap();
        let cfg = config(&temp, 25, 100);
        let error = run_configured(
            &cfg,
            &[
                "/d".into(),
                "/c".into(),
                "C:\\Windows\\System32\\ping.exe -n 6 127.0.0.1 >nul".into(),
            ],
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }
    #[test]
    fn rejects_unsafe_bounds_and_environment() {
        let temp = TempDir::new().unwrap();
        let mut cfg = config(&temp, 0, 100);
        let mut registry = AdapterRegistry {
            schema_version: SCHEMA.into(),
            adapters: vec![cfg.clone()],
        };
        assert!(validate_registry(&registry).is_err());
        cfg.timeout_ms = 100;
        cfg.environment.insert("PATH".into(), "unsafe".into());
        registry.adapters = vec![cfg];
        assert!(validate_registry(&registry).is_err());
    }
}
