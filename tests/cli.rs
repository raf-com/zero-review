use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

#[test]
fn help_names_control_plane() {
    Command::cargo_bin("zero-review")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Evidence-first code-review control plane",
        ));
}

#[test]
fn ledger_cli_stores_and_strictly_verifies_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let ledger = directory.path().join("ledger.jsonl");
    let store = directory.path().join("evidence");
    let source = directory.path().join("result.json");
    fs::write(&source, b"{\"status\":\"passed\"}").unwrap();

    Command::cargo_bin("zero-review")
        .unwrap()
        .args(["ledger-append", "--ledger"])
        .arg(&ledger)
        .args(["--evidence-root"])
        .arg(&store)
        .args([
            "--operation",
            "test",
            "--subject",
            "owner/repo@head",
            "--evidence",
        ])
        .arg(&source)
        .assert()
        .success();

    Command::cargo_bin("zero-review")
        .unwrap()
        .args(["ledger-verify", "--ledger"])
        .arg(&ledger)
        .args(["--strict-evidence", "--evidence-root"])
        .arg(&store)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"evidence\": \"verified\""));
}

#[test]
fn legacy_packet_gets_targeted_migration_error() {
    let directory = tempfile::tempdir().unwrap();
    let packet = directory.path().join("packet.json");
    fs::write(
        &packet,
        r#"{"schema_version":"zero-review.review-packet.v1"}"#,
    )
    .unwrap();
    Command::cargo_bin("zero-review")
        .unwrap()
        .args(["validate-review-packet", "--input"])
        .arg(packet)
        .args([
            "--repository",
            "owner/repo",
            "--pull-request-number",
            "1",
            "--base-sha",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--head-sha",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "migrate to zero-review.review-packet.v2",
        ));
}

#[test]
fn checkpoint_create_rejects_malformed_signature() {
    let directory = tempfile::tempdir().unwrap();
    let ledger = directory.path().join("ledger.jsonl");
    let store = directory.path().join("evidence");
    let source = directory.path().join("result.json");
    let out = directory.path().join("checkpoint.json");
    fs::write(&source, b"passed").unwrap();
    Command::cargo_bin("zero-review")
        .unwrap()
        .args(["ledger-append", "--ledger"])
        .arg(&ledger)
        .args(["--evidence-root"])
        .arg(&store)
        .args(["--operation", "test", "--subject", "repo", "--evidence"])
        .arg(&source)
        .assert()
        .success();
    Command::cargo_bin("zero-review")
        .unwrap()
        .args(["ledger-checkpoint-create", "--ledger"])
        .arg(&ledger)
        .args([
            "--ledger-id",
            "owner/repo",
            "--key-id",
            "key-1",
            "--created-at",
            "2026-09-04T12:00:00Z",
            "--signature",
            "x",
            "--out",
        ])
        .arg(out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("128 lowercase hexadecimal"));
}
