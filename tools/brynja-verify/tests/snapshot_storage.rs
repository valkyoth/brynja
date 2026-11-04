mod common;
use common::Fixture;
use serde_json::Value;
use std::fs;

fn expand(f: &Fixture, mut state: Value) -> Value {
    if state["schema"] == 2 {
        for rows in state["attempts"].as_object_mut().unwrap().values_mut() {
            for row in rows.as_array_mut().unwrap() {
                for field in ["before", "after"] {
                    if let Some(id) = row[field].as_str() {
                        row[field] = serde_json::from_slice(
                            &fs::read(f.root().join(format!("verification/snapshots/{id}.json")))
                                .unwrap(),
                        )
                        .unwrap();
                    }
                }
            }
        }
    }
    state["schema"] = 1.into();
    state
}

#[test]
fn explicit_migration_is_lossless_idempotent_and_does_not_scan_recover_or_execute() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    let mut legacy = expand(&f, f.state());
    legacy["attempts"]["md5/answers"][0]["outcome"] = "running".into();
    legacy["attempts"]["md5/answers"][0]["ended"] = Value::Null;
    legacy["attempts"]["md5/answers"][0]["after"] = Value::Null;
    f.write(
        "verification/results.json",
        &serde_json::to_string_pretty(&legacy).unwrap(),
    );
    let report = fs::read(f.root().join("docs/VERIFICATION_RESULTS.md")).unwrap();
    let executions = fs::read(f.root().join("executed")).unwrap();
    // Migration works with unavailable inputs and without any registry/tool discovery.
    fs::remove_file(f.root().join("md5/input")).unwrap();
    fs::remove_file(f.root().join("verification/checks.toml")).unwrap();
    f.ok(&["migrate-results"]);
    assert_eq!(f.state()["schema"], 2);
    assert_eq!(expand(&f, f.state()), legacy);
    assert_eq!(fs::read(f.root().join("executed")).unwrap(), executions);
    assert_eq!(
        fs::read(f.root().join("docs/VERIFICATION_RESULTS.md")).unwrap(),
        report
    );
    let compact = fs::read(f.root().join("verification/results.json")).unwrap();
    f.ok(&["migrate-results"]);
    assert_eq!(
        fs::read(f.root().join("verification/results.json")).unwrap(),
        compact
    );
}

#[test]
fn read_only_commands_accept_legacy_and_show_full_snapshots_after_migration() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    let legacy = expand(&f, f.state());
    let bytes = serde_json::to_string_pretty(&legacy).unwrap();
    f.write("verification/results.json", &bytes);
    let before = f.run(&["show", "md5", "answers"]);
    assert!(before.status.success());
    assert_eq!(
        fs::read_to_string(f.root().join("verification/results.json")).unwrap(),
        bytes
    );
    f.ok(&["migrate-results"]);
    let after = f.run(&["show", "md5", "answers"]);
    assert!(after.status.success());
    assert_eq!(before.stdout, after.stdout);
    // Matching-input selection still skips a real, previously successful run.
    let executed = fs::read(f.root().join("executed")).unwrap();
    f.ok(&["run", "md5", "--needed"]); // only the never-run boundaries check
    let now = fs::read_to_string(f.root().join("executed")).unwrap();
    assert_eq!(
        now,
        String::from_utf8(executed).unwrap() + "md5/boundaries\n"
    );
}

#[test]
fn lost_snapshot_blocks_execution_and_preserves_index() {
    let f = Fixture::new();
    f.ok(&["run", "md5", "answers"]);
    let state = f.state();
    let id = state["attempts"]["md5/answers"][0]["before"]
        .as_str()
        .unwrap();
    fs::remove_file(f.root().join(format!("verification/snapshots/{id}.json"))).unwrap();
    let bytes = fs::read(f.root().join("verification/results.json")).unwrap();
    let executions = fs::read(f.root().join("executed")).unwrap();
    for args in [
        vec!["migrate-results"],
        vec!["run", "md5", "--needed"],
        vec!["md5"],
        vec!["report"],
        vec!["show", "md5", "answers"],
    ] {
        let out = f.run(&args);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read snapshot"));
        assert_eq!(
            fs::read(f.root().join("verification/results.json")).unwrap(),
            bytes
        );
        assert_eq!(fs::read(f.root().join("executed")).unwrap(), executions);
    }
}

#[test]
fn migration_requires_existing_state_and_exclusive_lock() {
    use fs2::FileExt;
    let f = Fixture::new();
    assert!(!f.run(&["migrate-results"]).status.success());
    assert!(!f.root().join("verification/results.json").exists());
    f.ok(&["md5"]);
    let bytes = fs::read(f.root().join("verification/results.json")).unwrap();
    let lock = fs::File::open(f.root().join("verification/.runner/lock")).unwrap();
    lock.try_lock_exclusive().unwrap();
    let out = f.run(&["migrate-results"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("state lock"));
    assert_eq!(
        fs::read(f.root().join("verification/results.json")).unwrap(),
        bytes
    );
}

#[test]
fn snapshot_outputs_are_never_verification_inputs() {
    for path in [
        "verification/snapshots",
        "./verification/snapshots",
        "verification/./snapshots",
        "verification//snapshots",
        "verification/snapshots/a.json",
    ] {
        let f = Fixture::new();
        let registry = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
        f.write(
            "verification/checks.toml",
            &registry.replace(
                "paths=['md5','check.py']",
                &format!("paths=['md5','check.py','{path}']"),
            ),
        );
        assert!(!f.run(&["run", "md5", "answers"]).status.success());
        assert!(!f.root().join("executed").exists());
    }
    let f = Fixture::new();
    let registry = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    f.write(
        "verification/checks.toml",
        &registry.replace(
            "paths=['md5','check.py']",
            "paths=['md5','check.py','verification']\npatterns=['verification/snapshots/*.json']",
        ),
    );
    // Pattern registration of output paths is rejected, not read as evidence.
    assert!(!f.run(&["run", "md5", "answers"]).status.success());
    f.write(
        "verification/checks.toml",
        &registry.replace(
            "paths=['md5','check.py']",
            "paths=['md5','check.py','verification']",
        ),
    );
    f.ok(&["run", "md5", "answers"]);
    f.ok(&["md5"]);
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    // An unrelated unreferenced snapshot is not read or fingerprinted.
    f.write(
        "verification/snapshots/unreferenced.json",
        "incomplete orphan",
    );
    f.ok(&["md5"]);
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
}
