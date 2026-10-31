use serde_json::Value;
use std::{fs, process::Command, thread, time::Duration};

mod common;
use common::Fixture;

#[test]
fn registry_changes_during_execution_cannot_be_current_passes() {
    for edit in [
        "s.replace('execution_semantics=1', 'execution_semantics=2')",
        "s.replace(\"'check.py','md5/answers'\", \"'other.py','md5/answers'\")",
        "s.replace(\"paths=['md5','check.py']\", \"paths=['md5']\")",
        "s.replace(\"contains=['PASS']\", \"contains=['DIFFERENT']\")",
        "s.replace('timeout_seconds=2', 'timeout_seconds=3')",
        "'invalid TOML!'",
    ] {
        let f = Fixture::new();
        f.write("check.py", &format!(
            "from pathlib import Path\np=Path('verification/checks.toml')\ns=p.read_text()\np.write_text({edit})\nprint('PASS\\ntest result: ok. 1 passed; 0 failed; 0 ignored;')\n"
        ));
        assert!(!f.run(&["run", "md5", "answers"]).status.success());
        assert_eq!(
            f.attempt("md5/answers")["outcome"],
            "input_changed",
            "{edit}"
        );
    }
}

#[test]
fn unrelated_registry_edit_does_not_invalidate_a_run_but_stale_next_command_is_rejected() {
    let f = Fixture::new();
    f.write("check.py", "from pathlib import Path\np=Path('verification/checks.toml')\ns=p.read_text()\np.write_text(s.replace(\"'check.py','md5/boundaries'\", \"'other.py','md5/boundaries'\"))\nprint('PASS\\ntest result: ok. 1 passed; 0 failed; 0 ignored;')\n");
    let out = f.run(&["run", "md5", "--all"]);
    assert!(!out.status.success());
    assert_eq!(f.attempt("md5/answers")["outcome"], "passed");
    assert!(f.state()["attempts"].get("md5/boundaries").is_none());
    assert!(String::from_utf8_lossy(&out.stderr).contains("configuration changed"));
}

#[test]
fn scans_are_local_nonexecuting_and_do_not_churn() {
    let f = Fixture::new();
    f.ok(&["full-check"]);
    assert!(!f.root().join("executed").exists());
    let state = fs::read(f.root().join("verification/results.json")).unwrap();
    let report = fs::read(f.root().join("docs/VERIFICATION_RESULTS.md")).unwrap();
    f.ok(&["full-check"]);
    assert_eq!(
        state,
        fs::read(f.root().join("verification/results.json")).unwrap()
    );
    assert_eq!(
        report,
        fs::read(f.root().join("docs/VERIFICATION_RESULTS.md")).unwrap()
    );
    assert!(!f.run(&["missing"]).status.success());
    assert!(!f.run(&["run", "md5", "missing"]).status.success());
    assert!(!f.root().join("executed").exists());
}

#[test]
fn component_scans_do_not_refresh_neighbors_or_change_dates() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    f.ok(&["run", "aes", "answers"]);
    let md5 = f.attempt("md5/answers");
    let aes = f.view("aes/answers");
    f.write("aes/input", "new AES");
    f.ok(&["md5"]);
    assert_eq!(aes, f.view("aes/answers"));
    assert_eq!(md5, f.attempt("md5/answers"));
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    f.ok(&["full-check"]);
    assert!(
        f.view("aes/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("aes/input changed")
    );
    f.write("md5/input", "new MD5");
    f.ok(&["md5"]);
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("md5/input changed")
    );
    f.write("shared/input", "shared changed");
    f.ok(&["full-check"]);
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("shared/input changed")
    );
    assert!(
        f.view("aes/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("shared/input changed")
    );
}

#[test]
fn matching_additions_deletions_renames_and_unrelated_outputs() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    f.write("README.md", "unrelated docs");
    f.write("docs/VERIFICATION_RESULTS.md", "manual report edit");
    f.write("tools/help.txt", "new help");
    f.write("md5/target/output", "generated");
    f.ok(&["md5"]);
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    f.write("md5/new", "new untracked input");
    f.ok(&["md5"]);
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("md5/new added")
    );
    fs::remove_file(f.root().join("md5/new")).unwrap();
    f.ok(&["md5"]);
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    fs::rename(f.root().join("md5/input"), f.root().join("md5/renamed")).unwrap();
    f.ok(&["md5"]);
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("removed")
    );
}

#[test]
fn dirty_source_committed_later_preserves_execution_identity() {
    let f = Fixture::new();
    f.write("md5/input", "tested dirty");
    f.ok(&["run", "md5", "answers"]);
    let attempt = f.attempt("md5/answers");
    assert!(
        attempt["source"]
            .as_str()
            .unwrap()
            .starts_with("working tree based on")
    );
    f.git(&["add", "md5/input"]);
    f.git(&["commit", "-qm", "commit identical tested bytes"]);
    f.ok(&["md5"]);
    assert_eq!(attempt, f.attempt("md5/answers"));
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    f.ok(&["run", "md5", "--needed"]);
    assert_eq!(
        f.state()["attempts"]["md5/answers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        f.state()["attempts"]["md5/boundaries"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn later_failure_is_not_hidden_and_stops_remaining_work() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    let success = f.view("md5/answers")["last_success"].clone();
    f.write("mode", "fail");
    assert!(!f.run(&["run", "md5", "--all"]).status.success());
    assert_eq!(f.view("md5/answers")["result"], "failed");
    assert_eq!(success, f.view("md5/answers")["last_success"]);
    assert!(f.state()["attempts"]["md5/boundaries"].is_null());
    f.ok(&["md5"]);
    assert_eq!(f.view("md5/answers")["result"], "failed");
    f.write("mode", "pass");
    f.ok(&["run", "md5", "--needed"]);
    assert_eq!(
        f.state()["attempts"]["md5/answers"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn zero_tests_skips_and_mid_run_edits_never_pass() {
    for (mode, outcome) in [
        ("zero", "failed"),
        ("skip", "failed"),
        ("edit", "input_changed"),
    ] {
        let f = Fixture::new();
        f.write("mode", mode);
        assert!(!f.run(&["run", "md5", "answers"]).status.success());
        assert_eq!(f.attempt("md5/answers")["outcome"], outcome);
        assert!(f.view("md5/answers")["last_success"].is_null());
    }
}

#[test]
fn historical_pass_can_be_reused_after_reverting_inputs() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    let old = f.attempt("md5/answers");
    f.write("md5/input", "next");
    f.ok(&["run", "md5", "answers"]);
    f.write("md5/input", "md5 original");
    f.ok(&["md5"]);
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    assert_eq!(f.view("md5/answers")["performed_at"], old["ended"]);
    assert!(
        f.view("md5/answers")["result"]
            .as_str()
            .unwrap()
            .contains("latest overall attempt")
    );
}

#[test]
fn failure_on_reverted_inputs_is_not_hidden_by_a_later_different_pass() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    f.write("mode", "fail");
    assert!(!f.run(&["run", "md5", "answers"]).status.success());
    f.write("md5/input", "different state");
    f.write("mode", "pass");
    f.ok(&["run", "md5", "answers"]);
    f.write("md5/input", "md5 original");
    f.ok(&["md5"]);
    assert!(
        f.view("md5/answers")["result"]
            .as_str()
            .unwrap()
            .starts_with("failed")
    );
    assert_ne!(f.view("md5/answers")["freshness"], "Up to date");
}

#[test]
fn interrupted_record_and_render_failure_preserve_history() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    let mut state = f.state();
    state["attempts"]["md5/answers"][0]["outcome"] = "running".into();
    state["attempts"]["md5/answers"][0]["ended"] = Value::Null;
    f.write(
        "verification/results.json",
        &serde_json::to_string(&state).unwrap(),
    );
    f.ok(&["md5"]);
    assert_eq!(f.attempt("md5/answers")["outcome"], "interrupted");
    assert!(f.attempt("md5/answers")["ended"].is_null());
    // Make rendering fail AFTER execution by having the fake task replace the
    // report with a directory. The successful execution must already be saved.
    let script = fs::read_to_string(f.root().join("check.py")).unwrap()
        + "\np=pathlib.Path('docs/VERIFICATION_RESULTS.md'); p.unlink(); p.mkdir()\n";
    f.write("check.py", &script);
    assert!(!f.run(&["run", "md5", "answers"]).status.success());
    assert_eq!(f.attempt("md5/answers")["outcome"], "passed");
    fs::remove_dir(f.root().join("docs/VERIFICATION_RESULTS.md")).unwrap();
    f.ok(&["report"]);
    assert_eq!(f.attempt("md5/answers")["outcome"], "passed");
}

#[test]
fn lock_excludes_concurrent_mutation_and_signal_records_interruption() {
    let f = Fixture::new();
    f.write("mode", "slow");
    let mut child = Command::new(env!("CARGO_BIN_EXE_brynja-verify"))
        .arg("--root")
        .arg(f.root())
        .args(["run", "md5", "answers"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if f.root().join("executed").exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let out = f.run(&["full-check"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("state lock"));
    Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(!child.wait().unwrap().success());
    assert_eq!(f.attempt("md5/answers")["outcome"], "interrupted");
    f.ok(&["md5"]);
}

#[test]
fn timeout_and_unavailable_input_are_not_passes() {
    let f = Fixture::new();
    f.write("mode", "slow");
    assert!(!f.run(&["run", "md5", "answers"]).status.success());
    assert_eq!(f.attempt("md5/answers")["outcome"], "timed_out");
    fs::remove_file(f.root().join("md5/input")).unwrap();
    assert!(!f.run(&["run", "md5", "--needed"]).status.success());
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .starts_with("Unresolved")
    );
    assert_eq!(
        f.state()["attempts"]["md5/answers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn selected_dependency_metadata_and_execution_settings() {
    let f = Fixture::new();
    let registry = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    let extra = "\n[groups.md5.toml]\n'Cargo.toml'=['features.default']\n[[groups.md5.locks]]\npath='Cargo.lock'\npackages=['local','external']\n";
    f.write("verification/checks.toml", &(registry.clone() + extra));
    f.write(
        "Cargo.toml",
        "[package]\nversion='0.1.0'\n[features]\ndefault=[]\n",
    );
    let lock = "[[package]]\nname='local'\nversion='0.1.0'\n[[package]]\nname='external'\nversion='1.0.0'\nsource='registry+fixture'\nchecksum='a'\n[[package]]\nname='other'\nversion='2.0.0'\n";
    f.write("Cargo.lock", lock);
    f.ok(&["run", "md5", "answers"]);
    // A release number or unrelated dependency is not a cache key.
    f.write(
        "Cargo.toml",
        "[package]\nversion='0.9.0'\n[features]\ndefault=[]\n",
    );
    f.write(
        "Cargo.lock",
        &lock
            .replace("version='0.1.0'", "version='0.9.0'")
            .replace("version='2.0.0'", "version='3.0.0'"),
    );
    f.ok(&["md5"]);
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    f.write("Cargo.lock", &lock.replace("checksum='a'", "checksum='b'"));
    f.ok(&["md5"]);
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("package external changed")
    );
    f.write("Cargo.lock", lock);
    f.write("Cargo.toml", "[features]\ndefault=['changed']\n");
    f.ok(&["md5"]);
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("features.default")
    );
    f.write(
        "verification/checks.toml",
        &(registry.replace("execution_semantics=1", "execution_semantics=2") + extra),
    );
    f.ok(&["md5"]);
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("execution semantics")
    );
}

#[test]
fn custom_cargo_home_configuration_is_unresolved_without_running_cargo() {
    let f = Fixture::new();
    let registry = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    f.write(
        "verification/checks.toml",
        &registry.replace("command=['python3'", "command=['cargo'"),
    );
    f.write(
        "custom-home/config.toml",
        "[build]\nrustflags=['-Copt-level=2']\n",
    );
    let out = Command::new(env!("CARGO_BIN_EXE_brynja-verify"))
        .arg("--root")
        .arg(f.root())
        .arg("md5")
        .env("CARGO_HOME", f.root().join("custom-home"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("unresolved ambient Cargo configuration")
    );
    assert!(!f.root().join("executed").exists());
    f.write(
        "verification/checks.toml",
        &registry
            .replace("command=['python3'", "command=['cargo'")
            .replace("cwd='.'", "cwd='.'\nenvironment={CARGO_HOME='custom-home'}"),
    );
    f.ok(&["md5"]);
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("unresolved ambient Cargo configuration")
    );
}

#[test]
fn wrapper_content_is_an_effective_input_not_just_its_filename() {
    let f = Fixture::new();
    let registry = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    f.write("wrapper.sh", "wrapper version one");
    f.write(
        "verification/checks.toml",
        &registry
            .replace("command=['python3'", "command=['cargo'")
            .replace(
                "cwd='.'",
                "cwd='.'\nenvironment={RUSTC_WRAPPER='./wrapper.sh'}",
            ),
    );
    f.ok(&["md5"]);
    let before = f.view("md5/answers")["fingerprint"].clone();
    assert!(before.is_string());
    f.write("wrapper.sh", "wrapper version two");
    f.ok(&["md5"]);
    assert_ne!(before, f.view("md5/answers")["fingerprint"]);
    assert!(!f.root().join("executed").exists());
}
