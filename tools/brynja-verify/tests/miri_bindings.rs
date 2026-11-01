mod common;
use common::Fixture;
use serde_json::{Value, json};
use std::{fs, process::Command};

fn fragment(f: &Fixture) -> Value {
    let raw = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    f.write(
        "verification/checks.toml",
        &raw.replace("schema=1", "schema=1\nincludes=['verification/miri.json']"),
    );
    f.write("case.py", "from pathlib import Path\nwith Path('executed').open('a') as f: f.write('fake-case\\n')\nprint('MIRI_CASE_PASS: fake:0')\nprint('test result: ok. 1 passed; 0 failed; 0 ignored;')\n");
    let check = json!({"component":"md5", "id":"miri-routine-case", "name":"fake routine case", "establishes":"fixture only",
        "category":"miri-routine", "command":["python3", "case.py"], "cwd":".", "inputs":["case-inputs"],
        "timeout_seconds":2, "success":{"contains":["test result: ok."], "minimum_tests":1, "exact_tests":1, "unique_lines":["MIRI_CASE_PASS: fake:0"]}});
    let mut extended = check.clone();
    extended["id"] = json!("miri-extended-case");
    extended["category"] = json!("miri-extended");
    let fragment = json!({"schema":1, "groups":{"case-inputs":{"paths":["md5", "case.py"]}}, "checks":[check, extended]});
    f.write("verification/miri.json", &fragment.to_string());
    fragment
}

#[test]
fn profiles_are_explicit_and_single_case_execution_preserves_neighbors() {
    let f = Fixture::new();
    fragment(&f);
    for args in [
        vec!["run", "md5", "--needed"],
        vec!["run", "md5", "--all"],
        vec!["run", "md5", "--needed", "--category", "miri"],
    ] {
        assert!(!f.run(&args).status.success());
        assert!(!f.root().join("executed").exists());
    }
    f.ok(&["full-check"]);
    let neighbor = f.view("aes/answers");
    f.ok(&["run", "md5", "--needed", "--category", "miri-routine"]);
    assert_eq!(f.view("aes/answers"), neighbor);
    assert_eq!(
        fs::read_to_string(f.root().join("executed")).unwrap(),
        "fake-case\n"
    );
    assert!(
        f.state()["attempts"]
            .get("md5/miri-extended-case")
            .is_none()
    );
    let attempts = f.state()["attempts"].clone();
    f.ok(&["run", "md5", "--needed", "--category", "miri-routine"]);
    assert_eq!(f.state()["attempts"], attempts);
    f.ok(&["run", "md5", "miri-extended-case"]);
    assert_eq!(f.state()["attempts"].as_object().unwrap().len(), 2);
}

#[test]
fn markers_and_exact_counts_reject_fake_zero_duplicate_or_other_cases() {
    for output in [
        "test result: ok. 1 passed; 0 failed; 0 ignored;",
        "MIRI_CASE_PASS: fake:1\ntest result: ok. 1 passed; 0 failed; 0 ignored;",
        "MIRI_CASE_PASS: fake:0\nMIRI_CASE_PASS: fake:0\ntest result: ok. 1 passed; 0 failed; 0 ignored;",
        "MIRI_CASE_PASS: fake:0\ntest result: ok. 2 passed; 0 failed; 0 ignored;",
        "MIRI_CASE_PASS: fake:0\ntest result: ok. 0 passed; 0 failed; 0 ignored;",
        "MIRI_CASE_PASS: fake:0\ntest result: ok. 1 passed; 0 failed; 1 ignored;",
    ] {
        let f = Fixture::new();
        fragment(&f);
        f.write(
            "case.py",
            &format!("print({})", serde_json::to_string(output).unwrap()),
        );
        assert!(
            !f.run(&["run", "md5", "miri-routine-case"]).status.success(),
            "{output}"
        );
        assert_eq!(f.attempt("md5/miri-routine-case")["outcome"], "failed");
    }
}

#[test]
fn fragment_provenance_and_midrun_definition_changes_are_checked() {
    let f = Fixture::new();
    fragment(&f);
    f.git(&["add", "."]);
    f.git(&["commit", "-qm", "registered fixture"]);
    f.ok(&["run", "md5", "miri-routine-case"]);
    assert!(
        !f.attempt("md5/miri-routine-case")["source"]
            .as_str()
            .unwrap()
            .contains("working tree")
    );
    f.write("case.py", "import json\nfrom pathlib import Path\np=Path('verification/miri.json')\nd=json.loads(p.read_text())\nd['checks'][0]['success']['exact_tests']=2\np.write_text(json.dumps(d))\nprint('MIRI_CASE_PASS: fake:0')\nprint('test result: ok. 1 passed; 0 failed; 0 ignored;')\n");
    assert!(!f.run(&["run", "md5", "miri-routine-case"]).status.success());
    assert_eq!(
        f.attempt("md5/miri-routine-case")["outcome"],
        "input_changed"
    );
}

#[test]
fn malformed_duplicate_and_traversal_fragments_never_execute() {
    for mode in ["duplicate", "missing", "invalid", "traversal"] {
        let f = Fixture::new();
        let mut doc = fragment(&f);
        match mode {
            "duplicate" => {
                let c = doc["checks"][0].clone();
                doc["checks"].as_array_mut().unwrap().push(c);
                f.write("verification/miri.json", &doc.to_string());
            }
            "missing" => fs::remove_file(f.root().join("verification/miri.json")).unwrap(),
            "invalid" => f.write("verification/miri.json", "{}"),
            _ => {
                let raw = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
                f.write(
                    "verification/checks.toml",
                    &raw.replace("verification/miri.json", "../miri.json"),
                );
            }
        }
        assert!(!f.run(&["full-check"]).status.success());
        assert!(!f.root().join("executed").exists());
    }
}

#[test]
fn forbidden_inherited_flags_are_unavailable_not_executed() {
    let f = Fixture::new();
    let mut doc = fragment(&f);
    doc["checks"][0]["reject_environment"] = json!(["MIRIFLAGS"]);
    f.write("verification/miri.json", &doc.to_string());
    let output = Command::new(env!("CARGO_BIN_EXE_brynja-verify"))
        .arg("--root")
        .arg(f.root())
        .args(["run", "md5", "miri-routine-case"])
        .env("MIRIFLAGS", "-Zmiri-disable-validation")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("clear inherited override"));
    assert!(!f.root().join("executed").exists());
    assert!(f.state()["attempts"].as_object().unwrap().is_empty());
}

#[test]
fn scan_cache_is_temporary_and_execution_still_reads_changed_inputs() {
    let f = Fixture::new();
    fragment(&f);
    f.ok(&["run", "md5", "miri-routine-case"]);
    f.ok(&["full-check"]);
    f.write("md5/input", "changed since previous scan");
    f.ok(&["md5"]);
    assert!(
        f.view("md5/miri-routine-case")["freshness"]
            .as_str()
            .unwrap()
            .contains("md5/input changed")
    );
    f.ok(&["run", "md5", "--needed", "--category", "miri-routine"]);
    assert_eq!(
        f.state()["attempts"]["md5/miri-routine-case"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    f.write("case.py", "from pathlib import Path\nPath('md5/input').write_text('edited while running')\nprint('MIRI_CASE_PASS: fake:0')\nprint('test result: ok. 1 passed; 0 failed; 0 ignored;')\n");
    assert!(!f.run(&["run", "md5", "miri-routine-case"]).status.success());
    assert_eq!(
        f.attempt("md5/miri-routine-case")["outcome"],
        "input_changed"
    );
}

#[test]
fn local_release_number_is_not_a_new_input_but_dependency_origin_is() {
    let f = Fixture::new();
    let mut doc = fragment(&f);
    doc["groups"]["case-inputs"]["normalize_local_versions"] = json!(true);
    doc["groups"]["case-inputs"]["toml"] = json!({"dependencies.toml":["dependencies"]});
    f.write("verification/miri.json", &doc.to_string());
    f.write("dependencies.toml", "[dependencies.local]\npath='local'\nversion='1.0.0'\n[dependencies.external]\nversion='1.0.0'\n");
    f.ok(&["run", "md5", "miri-routine-case"]);
    let original = f.view("md5/miri-routine-case")["fingerprint"].clone();
    let raw = fs::read_to_string(f.root().join("dependencies.toml")).unwrap();
    f.write(
        "dependencies.toml",
        &raw.replacen("version='1.0.0'", "version='2.0.0'", 1),
    );
    f.ok(&["md5"]);
    assert_eq!(f.view("md5/miri-routine-case")["fingerprint"], original);
    f.write(
        "dependencies.toml",
        &raw.replace("path='local'", "git='https://example.invalid/dependency'"),
    );
    f.ok(&["md5"]);
    assert_ne!(f.view("md5/miri-routine-case")["fingerprint"], original);
    f.write(
        "dependencies.toml",
        &raw.replace(
            "[dependencies.external]\nversion='1.0.0'",
            "[dependencies.external]\nversion='2.0.0'",
        ),
    );
    f.ok(&["md5"]);
    assert_ne!(f.view("md5/miri-routine-case")["fingerprint"], original);
}
