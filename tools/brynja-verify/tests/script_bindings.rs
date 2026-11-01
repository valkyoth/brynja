mod common;
use common::Fixture;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};

#[test]
fn pki_policy_ignores_unread_package_metadata_but_tracks_actual_policy_fields() {
    let f = Fixture::new();
    let doc: Value = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../verification/extra-checks.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let checks: Vec<_> = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            c["command"][1] == "scripts/pki/check-der-reader.py"
                || c["command"][1] == "scripts/pki/test-der-reader.py"
        })
        .cloned()
        .collect();
    assert_eq!(checks.len(), 2);
    let mut groups = BTreeMap::new();
    for check in &checks {
        for name in check["inputs"].as_array().unwrap() {
            let name = name.as_str().unwrap();
            let group = doc["groups"][name].clone();
            if let Some(paths) = group["paths"].as_array() {
                for path in paths {
                    f.write(path.as_str().unwrap(), "synthetic input only");
                }
            }
            groups.insert(name, group);
        }
        f.write(
            check["command"][1].as_str().unwrap(),
            &format!(
                "print({})\n",
                serde_json::to_string(&check["success"]["unique_lines"][0]).unwrap()
            ),
        );
    }
    let manifest = "[package]\nversion='0.1.0'\n[dependencies]\nbrynja-core={workspace=true}\n[features]\ndefault=[]\n";
    let policy =
        "[packages.brynja-pki]\nclass='modern-shared'\n[packages.unrelated]\nclass='unrelated'\n";
    f.write("crates/brynja-pki/Cargo.toml", manifest);
    f.write("package-policy.toml", policy);
    let registry = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    f.write(
        "verification/checks.toml",
        &registry.replace("schema=1", "schema=1\nincludes=['verification/pki.json']"),
    );
    f.write(
        "verification/pki.json",
        &json!({"schema":1,"groups":groups,"checks":checks}).to_string(),
    );
    f.ok(&["run", "pki", "--all"]);
    let attempts = f.state()["attempts"].clone();
    f.write(
        "crates/brynja-pki/Cargo.toml",
        &manifest.replace("0.1.0", "0.2.0"),
    );
    f.write(
        "package-policy.toml",
        &policy.replace("class='unrelated'", "class='another'"),
    );
    f.ok(&["pki"]);
    for check in &checks {
        let key = format!("pki/{}", check["id"].as_str().unwrap());
        let freshness = f.view(&key)["freshness"].as_str().unwrap().to_owned();
        if check["command"][1] == "scripts/pki/check-der-reader.py" {
            assert_eq!(freshness, "Up to date");
        } else {
            assert!(freshness.contains("Cargo.toml") || freshness.contains("package-policy.toml"));
        }
    }
    f.write(
        "crates/brynja-pki/Cargo.toml",
        &manifest.replace("default=[]", "default=['changed']"),
    );
    f.ok(&["pki"]);
    for check in &checks {
        let key = format!("pki/{}", check["id"].as_str().unwrap());
        assert_ne!(f.view(&key)["freshness"], "Up to date");
    }
    assert_eq!(f.state()["attempts"], attempts);
}

#[test]
fn registered_contract_scope_and_completion_are_enforced_without_real_checks() {
    let f = Fixture::new();
    let document: Value = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../verification/extra-checks.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let check = document["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["command"][1] == "scripts/foundations/check-provider-contract.py")
        .unwrap()
        .clone();
    let mut groups = BTreeMap::new();
    for name in check["inputs"].as_array().unwrap() {
        let name = name.as_str().unwrap();
        let group = document["groups"][name].clone();
        if let Some(paths) = group["paths"].as_array() {
            for path in paths {
                f.write(path.as_str().unwrap(), "synthetic input only");
            }
        }
        groups.insert(name, group);
    }
    let script = check["command"][1].as_str().unwrap();
    let marker = check["success"]["unique_lines"][0].as_str().unwrap();
    f.write(script, &format!(
        "import os, pathlib\nassert os.environ['PYTHONOPTIMIZE'] == '0'\nassert os.environ['PYTHONNOUSERSITE'] == '1'\nassert os.environ['PYTHONDONTWRITEBYTECODE'] == '1'\nmode = pathlib.Path('mode').read_text() if pathlib.Path('mode').exists() else 'pass'\nif mode != 'missing': print({0})\nif mode == 'duplicate': print({0})\n",
        serde_json::to_string(marker).unwrap()
    ));
    let raw = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    f.write(
        "verification/checks.toml",
        &raw.replace(
            "schema=1",
            "schema=1\nincludes=['verification/scripts.json']",
        ),
    );
    f.write(
        "verification/scripts.json",
        &json!({"schema":1,"groups":groups,"checks":[check]}).to_string(),
    );
    let component = check["component"].as_str().unwrap();
    let id = check["id"].as_str().unwrap();
    let key = format!("{component}/{id}");
    f.ok(&["run", "md5", "answers"]);
    let neighbor = f.attempt("md5/answers");
    f.ok(&["run", component, id]);
    let success = f.attempt(&key);
    assert_eq!(success["outcome"], "passed");
    f.write("aes/input", "unrelated change");
    f.ok(&[component]);
    assert_eq!(f.view(&key)["freshness"], "Up to date");
    assert_eq!(f.attempt(&key), success);
    f.write(
        "scripts/foundations/provider_contract_policy.py",
        "changed relevant helper",
    );
    f.ok(&[component]);
    assert!(
        f.view(&key)["freshness"]
            .as_str()
            .unwrap()
            .contains("provider_contract_policy.py")
    );
    for mode in ["missing", "duplicate"] {
        f.write("mode", mode);
        assert!(!f.run(&["run", component, id]).status.success());
        assert_eq!(f.attempt(&key)["outcome"], "failed");
        assert_eq!(f.state()["attempts"][&key][0], success);
    }
    assert_eq!(f.attempt("md5/answers"), neighbor);
}
