mod common;
use common::Fixture;
use sha2::{Digest, Sha256};
use std::{
    fs,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn rotation_is_explicit_lossless_bounded_and_does_not_reuse_archived_passes() {
    let f = Fixture::new();
    let original_input = fs::read_to_string(f.root().join("md5/input")).unwrap();
    f.ok(&["run", "md5", "answers"]);
    f.write("md5/input", "second inputs");
    f.ok(&["run", "md5", "answers"]);
    let old = f.state();
    let executions = fs::read(f.root().join("executed")).unwrap();
    f.ok(&["rotate-results"]);
    let live = f.state();
    assert_eq!(live["schema"], 3);
    assert_eq!(
        live["attempts"]["md5/answers"],
        serde_json::json!([old["attempts"]["md5/answers"][1]])
    );
    assert_eq!(live["views"], serde_json::json!({}));
    assert!(
        fs::read_to_string(f.root().join("docs/VERIFICATION_RESULTS.md"))
            .unwrap()
            .contains("invalidated")
    );
    let id = live["archives"][0].as_str().unwrap();
    let bytes = fs::read(f.root().join(format!("verification/archives/{id}.json"))).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), id);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        old
    );
    assert_eq!(f.run(&["show-archive", id]).stdout, bytes);
    assert_eq!(
        f.run(&["list-archives"]).stdout,
        format!("{id}\n").as_bytes()
    );
    f.ok(&["rotate-results"]);
    assert_eq!(f.state(), live);
    assert_eq!(fs::read(f.root().join("executed")).unwrap(), executions);
    f.ok(&["md5"]);
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    f.write("md5/input", &original_input);
    f.ok(&["md5"]);
    assert_ne!(f.view("md5/answers")["freshness"], "Up to date");
    // A second rotation preserves the first checkpoint reference.
    f.ok(&["run", "md5", "answers"]);
    f.ok(&["rotate-results"]);
    assert_eq!(f.state()["archives"].as_array().unwrap().len(), 2);
    assert_eq!(f.state()["archives"][0], id);
    assert_eq!(f.run(&["show-archive", id]).stdout, bytes);
}

#[test]
fn archives_fail_closed_on_corruption_missing_objects_and_invalid_ids() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    f.ok(&["run", "md5", "answers"]);
    f.ok(&["rotate-results"]);
    let state = f.state();
    let id = state["archives"][0].as_str().unwrap();
    let path = f.root().join(format!("verification/archives/{id}.json"));
    let original = fs::read(&path).unwrap();
    fs::write(&path, b"corrupt").unwrap();
    assert!(!f.run(&["show-archive", id]).status.success());
    fs::write(&path, original).unwrap();
    for id in ["../results", &"A".repeat(64), &"f".repeat(64)] {
        assert!(!f.run(&["show-archive", id]).status.success());
    }
    let object = state["attempts"]["md5/answers"][0]["before"]
        .as_str()
        .unwrap();
    fs::remove_file(
        f.root()
            .join(format!("verification/snapshots/{object}.json")),
    )
    .unwrap();
    assert!(!f.run(&["show-archive", id]).status.success());
    assert_eq!(f.state(), state);
}

#[test]
fn duplicate_attempt_groups_and_views_are_rejected_without_replacing_evidence() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    let state = f.state();
    for (field, value) in [
        ("attempts", state["attempts"]["md5/answers"].clone()),
        ("views", state["views"]["md5/answers"].clone()),
    ] {
        let bytes = format!(
            "{{\"schema\":2,\"{field}\":{{\"md5/answers\":{value},\"md5/answers\":{value}}}}}"
        );
        f.write("verification/results.json", &bytes);
        let out = f.run(&["migrate-results"]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("duplicate"));
        assert_eq!(
            fs::read_to_string(f.root().join("verification/results.json")).unwrap(),
            bytes
        );
    }
}

#[test]
fn rotation_refuses_running_state_and_respects_lock_without_needing_registry() {
    use fs2::FileExt;
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    f.ok(&["run", "md5", "answers"]);
    let original = f.state();
    let mut running = original.clone();
    running["attempts"]["md5/answers"][1]["outcome"] = "running".into();
    f.write("verification/results.json", &running.to_string());
    assert!(!f.run(&["rotate-results"]).status.success());
    assert_eq!(f.state(), running);
    f.write("verification/results.json", &original.to_string());
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.root().join("verification/.runner/lock"))
        .unwrap();
    lock.lock_exclusive().unwrap();
    assert!(!f.run(&["rotate-results"]).status.success());
    assert_eq!(f.state(), original);
    drop(lock);
    f.write("verification/checks.toml", "invalid registry");
    f.ok(&["rotate-results"]);
    assert_eq!(f.state()["archives"].as_array().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn fifo_artifact_fails_promptly_without_waiting_for_a_writer() {
    fifo_rejected(false);
    fifo_rejected(true);
}

#[cfg(unix)]
fn fifo_rejected(snapshot: bool) {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    let path = if snapshot {
        let id = f.state()["attempts"]["md5/answers"][0]["before"]
            .as_str()
            .unwrap()
            .to_owned();
        f.root().join(format!("verification/snapshots/{id}.json"))
    } else {
        f.root().join("verification/results.json")
    };
    fs::remove_file(&path).unwrap();
    assert!(
        Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_brynja-verify"))
        .args(["--root", f.root().to_str().unwrap(), "report"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if start.elapsed() > Duration::from_secs(3) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("FIFO blocked before rejection");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn full_scan_warns_at_capacity_threshold_without_executing() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    let executions = fs::read(f.root().join("executed")).unwrap();
    let mut state = f.state();
    let row = state["attempts"]["md5/answers"][0].clone();
    for (count, warning) in [(7499, false), (7500, true)] {
        state["attempts"]["md5/answers"] = serde_json::json!(vec![row.clone(); count]);
        f.write("verification/results.json", &state.to_string());
        let out = f.run(&["full-check"]);
        assert!(out.status.success());
        assert_eq!(
            String::from_utf8_lossy(&out.stderr).contains("Storage warning: attempts"),
            warning
        );
    }
    assert_eq!(fs::read(f.root().join("executed")).unwrap(), executions);
}
