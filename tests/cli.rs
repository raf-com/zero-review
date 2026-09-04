use assert_cmd::Command;
use predicates::prelude::*;

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
