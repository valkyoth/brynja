mod common;
use common::Fixture;
use serde_json::{Value, json};
use std::{fs, path::Path};

#[test]
fn assessment_completion_signals_reject_partial_duplicate_and_skipped_results() {
    let document: Value = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../verification/extra-checks.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let checks: Vec<_> = document["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            c["inputs"].as_array().unwrap().iter().any(|k| {
                k == "assessment-python"
                    || k == "hosted-python"
                    || k == "compiler-python"
                    || k == "codegen-python"
                    || k == "shell-tools"
                    || k == "checker-python"
                    || k == "source-policy-python"
                    || k == "legacy-policy-python"
                    || k == "hardened-python"
                    || k == "inventory-python"
                    || k == "control-python"
                    || k == "record-policy-python"
                    || k == "package-python"
                    || k == "execution-python"
                    || k == "owner-python"
                    || k == "acceptance-python"
                    || k == "final-component-python"
            })
        })
        .cloned()
        .collect();
    assert_eq!(checks.len(), 255);
    for mut check in checks {
        let f = Fixture::new();
        let lines: Vec<_> = ["unique_lines", "unique_prefixes"]
            .into_iter()
            .flat_map(|field| check["success"][field].as_array().into_iter().flatten())
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let mut good = lines.join("\n") + "\n";
        let tests = check["success"]["exact_tests"]
            .as_u64()
            .or_else(|| check["success"]["minimum_tests"].as_u64())
            .unwrap_or(0);
        if tests > 0 {
            good.push_str(&format!("test result: ok. {tests} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"));
        }
        for marker in check["success"]["contains"].as_array().unwrap() {
            let marker = marker.as_str().unwrap();
            if !good.contains(marker) {
                good.push_str(&format!("{marker}0.001s\n"));
            }
        }
        // Keep the real acceptance configuration; replace only execution and
        // inputs with an explicitly synthetic command in a temporary repository.
        check["command"] = json!(["python3", "fake.py"]);
        check["inputs"] = json!(["fake"]);
        check.as_object_mut().unwrap().remove("platform");
        f.write(
            "fake.py",
            "from pathlib import Path\nprint(Path('fake-output').read_text(), end='')\n",
        );
        let registry = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
        f.write(
            "verification/checks.toml",
            &registry.replace("schema=1", "schema=1\nincludes=['verification/fake.json']"),
        );
        f.write("verification/fake.json", &json!({"schema":1,"groups":{"fake":{"paths":["fake.py","fake-output"]}},"checks":[check]}).to_string());
        let component = check["component"].as_str().unwrap();
        let id = check["id"].as_str().unwrap();
        let key = format!("{component}/{id}");
        f.write("fake-output", &good);
        f.ok(&["run", component, id]);
        let success = f.attempt(&key);
        let mut bad = vec![String::new()];
        if let Some(line) = lines.first() {
            bad.push(good.clone() + line + "\n");
        }
        if check["success"]["minimum_tests"].as_u64().unwrap_or(0) > 0 {
            bad.push(good.replace(&format!("{tests} passed;"), "0 passed;"));
            bad.push(good.replace("0 failed;", "1 failed;"));
            if check["success"]["allow_ignored"] != true {
                bad.push(good.replace("0 ignored;", "1 ignored;"));
            } else {
                // Compatibility wrappers deliberately leave native-only tests
                // ignored. That is valid only with executed required work;
                // an all-skipped population must still fail.
                f.write("fake-output", &good.replace("0 ignored;", "1 ignored;"));
                f.ok(&["run", component, id]);
                bad.push(
                    good.replace(&format!("{tests} passed;"), "0 passed;")
                        .replace("0 ignored;", "1 ignored;"),
                );
            }
            if check["success"]["exact_tests"].is_number() {
                bad.push(good.replace(
                    &format!("{tests} passed;"),
                    &format!("{} passed;", tests + 1),
                ));
            }
        }
        for marker in &lines {
            bad.push(good.replace(&(marker.to_owned() + "\n"), ""));
        }
        if good.contains("\nRan ") {
            bad.push(good.replace("OK\n", "OK (skipped=1)\n"));
            for marker in check["success"]["contains"].as_array().unwrap() {
                let marker = marker.as_str().unwrap();
                if marker.starts_with("\nRan ") {
                    bad.push(good.replace(marker, "\nRan 0 tests in "));
                }
            }
        }
        for output in bad {
            assert_ne!(output, good, "fixture must actually mutate the transcript");
            f.write("fake-output", &output);
            assert!(
                !f.run(&["run", component, id]).status.success(),
                "accepted incomplete {key}: {output}"
            );
            assert_eq!(f.attempt(&key)["outcome"], "failed");
            assert_eq!(f.state()["attempts"][&key][0], success);
        }
    }
}
