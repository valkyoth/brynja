mod common;
use common::Fixture;
use serde_json::json;
use std::fs;

fn catalog(f: &Fixture) {
    let path = f.root().join("verification/checks.toml");
    let registry = fs::read_to_string(path).unwrap();
    f.write(
        "verification/checks.toml",
        &registry.replace("schema=1", "schema=1\ncatalog='verification/catalog.json'"),
    );
    let entry = json!({"id":"miri-example", "families":["md5", "newcomponent"], "phase":"miri",
    "label":"old matrix", "command":["python3", "check.py", "must-not-run"], "environment":{},
    "stdin":null, "definition":{}, "reason":"Missing scoped inputs and platform binding",
    "history":[
        {"result":"passed", "ended":"2026-01-01T01:00:00Z", "source":"OLD_SOURCE", "campaign_commit":"OLD", "receipt":"old-receipt", "log_sha256":"old-log", "reference":"old.json#0"},
        {"result":"failed", "ended":"2026-01-02T01:00:00Z", "source":"FAILED_SOURCE", "campaign_commit":"FAILED", "receipt":"failed-receipt", "log_sha256":"failed-log", "reference":"old.json#1"}
    ]});
    f.write(
        "verification/catalog.json",
        &json!({"schema":1, "entries":[entry]}).to_string(),
    );
}

#[test]
fn full_inventory_is_visible_without_execution_or_fabricated_current_passes() {
    let f = Fixture::new();
    catalog(&f);
    f.ok(&["run", "md5", "answers"]);
    let attempts = f.state()["attempts"].clone();
    let output = f.run(&["full-check"]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("All runnable registrations refreshed"));
    assert!(!text.contains("Other components retain"));
    assert!(text.contains("newcomponent"));
    assert_eq!(f.state()["attempts"], attempts);
    assert!(
        !fs::read_to_string(f.root().join("executed"))
            .unwrap()
            .contains("must-not-run")
    );
    let list = f.run(&["list", "md5", "miri"]);
    assert!(list.status.success());
    let text = String::from_utf8_lossy(&list.stdout);
    assert!(text.contains("historical failed at 2026-01-02T01:00:00Z"));
    let show = f.run(&["show", "md5", "miri-example"]);
    let text = String::from_utf8_lossy(&show.stdout);
    assert!(text.contains("OLD_SOURCE") && text.contains("FAILED_SOURCE"));
    assert!(text.contains("UNRESOLVED"));
    assert_eq!(f.state()["attempts"], attempts);
}

#[test]
fn unresolved_and_unknown_selection_never_run_the_catalog_command() {
    let f = Fixture::new();
    catalog(&f);
    for args in [
        vec!["run", "md5", "miri-example"],
        vec!["run", "newcomponent", "--needed"],
        vec!["show", "md5", "unknown"],
        vec!["list", "md5", "unknown"],
    ] {
        assert!(!f.run(&args).status.success(), "{args:?}");
    }
    assert!(!f.root().join("executed").exists());
    let output = f.run(&["run", "md5", "--needed"]);
    assert!(!output.status.success()); // catalog remains explicitly incomplete
    assert_eq!(
        fs::read_to_string(f.root().join("executed")).unwrap(),
        "md5/answers\nmd5/boundaries\n"
    );
    assert_eq!(f.attempt("md5/answers")["outcome"], "passed");
}

#[test]
fn malformed_missing_or_duplicate_inventory_is_not_silently_hidden() {
    let f = Fixture::new();
    catalog(&f);
    let path = f.root().join("verification/catalog.json");
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let duplicate = doc["entries"][0].clone();
    doc["entries"].as_array_mut().unwrap().push(duplicate);
    f.write("verification/catalog.json", &doc.to_string());
    assert!(!f.run(&["full-check"]).status.success());
    f.write("verification/catalog.json", "invalid");
    assert!(!f.run(&["md5"]).status.success());
    fs::remove_file(path).unwrap();
    assert!(!f.run(&["md5"]).status.success());
    assert!(!f.root().join("executed").exists());
}

#[test]
fn references_are_not_pending_work_and_bound_entries_keep_original_history() {
    let f = Fixture::new();
    catalog(&f);
    let path = f.root().join("verification/catalog.json");
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    doc["entries"][0]["phase"] = json!("retired-history");
    f.write("verification/catalog.json", &doc.to_string());
    f.ok(&["run", "md5", "--needed"]); // A retired identity is not missing work.
    let list = f.run(&["list", "md5", "retired-history"]);
    assert!(String::from_utf8_lossy(&list.stdout).contains("reference only"));

    doc["entries"][0]["phase"] = json!("portable");
    doc["entries"][0]["id"] = json!("answers");
    f.write("verification/catalog.json", &doc.to_string());
    let attempts = f.state()["attempts"].clone();
    let output = f.run(&["show", "md5", "answers"]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("OLD_SOURCE") && text.contains("FAILED_SOURCE"));
    assert!(text.contains("historical_catalog") && text.contains("attempts"));
    assert_eq!(f.state()["attempts"], attempts);
    let list = f.run(&["list", "md5", "portable"]);
    assert_eq!(
        String::from_utf8_lossy(&list.stdout)
            .lines()
            .filter(|line| line.starts_with("answers "))
            .count(),
        1
    );
}

#[test]
fn category_selection_is_bounded_and_unknown_category_never_executes() {
    let f = Fixture::new();
    let raw = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    f.write(
        "verification/checks.toml",
        &raw.replace("id='boundaries'", "id='boundaries'\ncategory='asan'"),
    );
    assert!(
        !f.run(&["run", "md5", "--all", "--category", "typo"])
            .status
            .success()
    );
    assert!(!f.root().join("executed").exists());
    f.ok(&["run", "md5", "--needed", "--category", "asan"]);
    assert_eq!(
        fs::read_to_string(f.root().join("executed")).unwrap(),
        "md5/boundaries\n"
    );
    assert!(f.state()["attempts"].get("md5/answers").is_none());
    let attempts = f.state()["attempts"].clone();
    f.ok(&["run", "md5", "--needed", "--category", "asan"]);
    assert_eq!(f.state()["attempts"], attempts);
    f.ok(&["run", "md5", "--all", "--category", "asan"]);
    assert_eq!(
        f.state()["attempts"]["md5/boundaries"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn unavailable_platform_never_executes_or_records_success() {
    let f = Fixture::new();
    let raw = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    f.write(
        "verification/checks.toml",
        &raw.replace(
            "id='boundaries'",
            "id='boundaries'\nplatform='unavailable-platform'",
        ),
    );
    let output = f.run(&["run", "md5", "boundaries"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires unavailable-platform"));
    assert!(!f.root().join("executed").exists());
    assert!(f.state()["attempts"].get("md5/boundaries").is_none());
}

#[test]
fn bound_history_is_displayed_but_never_becomes_a_current_pass() {
    let f = Fixture::new();
    catalog(&f);
    let path = f.root().join("verification/catalog.json");
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    doc["entries"][0]["phase"] = json!("portable");
    doc["entries"][0]["id"] = json!("answers");
    f.write("verification/catalog.json", &doc.to_string());
    let output = f.run(&["md5"]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Historical failed") && text.contains("2026-01-02T01:00:00Z"));
    assert!(text.contains("not a current pass"));
    assert!(text.contains("No execution recorded by this runner."));
    assert!(
        !text
            .lines()
            .any(|line| line.contains("Historical failed") && line.contains("No recorded result"))
    );
    let show = f.run(&["show", "md5", "answers"]);
    let shown: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(shown["view"]["result"], "Historical failed");
    assert_eq!(shown["view"]["performed_at"], "2026-01-02T01:00:00Z");
    assert!(shown["attempts"].is_null());
    assert!(f.state()["attempts"].as_object().unwrap().is_empty());
    f.write("mode", "fail");
    assert!(!f.run(&["run", "md5", "answers"]).status.success());
    let output = f.run(&["md5"]);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Historical failed"));
    assert_eq!(f.attempt("md5/answers")["outcome"], "failed");
}

#[test]
fn old_zero_proof_inventory_is_reference_only_not_pending_execution() {
    let f = Fixture::new();
    catalog(&f);
    let path = f.root().join("verification/catalog.json");
    let mut doc: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    doc["entries"][0]["phase"] = json!("inventory-only");
    doc["entries"][0]["reason"] = json!("Old setup selector ran no proofs");
    f.write("verification/catalog.json", &doc.to_string());
    f.ok(&["run", "md5", "--needed"]);
    let list = f.run(&["list", "md5", "inventory-only"]);
    assert!(String::from_utf8_lossy(&list.stdout).contains("reference only"));
    assert!(!f.run(&["run", "md5", "miri-example"]).status.success());
    let show = f.run(&["show", "md5", "miri-example"]);
    assert!(String::from_utf8_lossy(&show.stdout).contains("FAILED_SOURCE"));
}

#[test]
fn manual_diagnostics_preserve_commands_and_history_but_never_run_implicitly() {
    let f = Fixture::new();
    catalog(&f);
    let mut doc: serde_json::Value =
        serde_json::from_slice(&fs::read(f.root().join("verification/catalog.json")).unwrap())
            .unwrap();
    doc["entries"][0]["manual_diagnostic"] = json!(true);
    doc["entries"][0]["reason"] =
        json!("Explicit legacy campaign; owner-approved manual diagnostic");
    f.write("verification/catalog.json", &doc.to_string());
    f.ok(&["run", "md5", "--needed"]);
    let list = f.run(&["list", "md5", "miri"]);
    assert!(String::from_utf8_lossy(&list.stdout).contains("manual diagnostic"));
    let show = f.run(&["show", "md5", "miri-example"]);
    let text = String::from_utf8_lossy(&show.stdout);
    assert!(
        text.contains("Manual diagnostic")
            && text.contains("OLD_SOURCE")
            && text.contains("must-not-run")
    );
    assert!(!f.run(&["run", "md5", "miri-example"]).status.success());
    assert_eq!(
        fs::read_to_string(f.root().join("executed")).unwrap(),
        "md5/answers\nmd5/boundaries\n"
    );
    doc["entries"][0]["id"] = json!("answers");
    doc["entries"][0]["phase"] = json!("portable");
    f.write("verification/catalog.json", &doc.to_string());
    assert!(!f.run(&["md5"]).status.success());
}

#[test]
fn shared_binding_is_visible_from_all_families_without_duplicate_execution() {
    let f = Fixture::new();
    catalog(&f);
    let mut doc: serde_json::Value =
        serde_json::from_slice(&fs::read(f.root().join("verification/catalog.json")).unwrap())
            .unwrap();
    doc["entries"][0]["id"] = json!("answers");
    doc["entries"][0]["phase"] = json!("portable");
    f.write("verification/catalog.json", &doc.to_string());
    let list = f.run(&["list", "newcomponent"]);
    assert!(list.status.success());
    assert!(String::from_utf8_lossy(&list.stdout).contains("use run md5 answers"));
    let show = f.run(&["show", "newcomponent", "answers"]);
    let shown: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(shown["registration"]["component"], "md5");
    assert!(!f.root().join("executed").exists());
    assert!(!f.run(&["run", "newcomponent", "answers"]).status.success());
}
