mod common;
use common::Fixture;
use std::fs;

fn grouped_fixture() -> Fixture {
    let f = Fixture::new();
    let mut registry: toml::Value =
        toml::from_str(&fs::read_to_string(f.root().join("verification/checks.toml")).unwrap())
            .unwrap();
    let checks = registry["checks"].as_array_mut().unwrap();
    for (i, check) in checks[..2].iter_mut().enumerate() {
        check["name"] = format!("md5-bulk:{i} [routine]").into();
        check["command"] = toml::Value::Array(
            ["python3", "check.py", "md5-bulk"]
                .map(|s| s.into())
                .to_vec(),
        );
        check
            .as_table_mut()
            .unwrap()
            .insert("category".into(), "miri-routine".into());
        check.as_table_mut().unwrap().insert(
            "environment".into(),
            toml::Value::Table(
                [("CASE".into(), i.to_string().into())]
                    .into_iter()
                    .collect(),
            ),
        );
    }
    let mut extended = checks[0].clone();
    extended["id"] = "extended".into();
    extended["name"] = "md5-bulk:0 [extended]".into();
    extended["category"] = "miri-extended".into();
    checks.push(extended);
    f.write(
        "verification/checks.toml",
        &toml::to_string(&registry).unwrap(),
    );
    f
}

fn status(f: &Fixture, args: &[&str]) -> String {
    let output = f.run(args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn groups_cases_not_dates_keeps_profiles_separate_and_details_accessible() {
    let f = grouped_fixture();
    let text = status(&f, &["md5"]);
    assert_eq!(text.matches(" / md5-bulk\n").count(), 2);
    assert!(text.contains("Configurations: 2 | Current passes: 0/2 | Not run: 2"));
    assert!(text.contains("md5 / miri-extended / md5-bulk"));
    assert!(!text.contains("md5-bulk:0"));
    assert!(!text.contains("Assessments awaiting"));
    assert!(!f.root().join("executed").exists());
    let filtered = status(&f, &["md5", "--category", "miri-routine"]);
    assert!(!filtered.contains("miri-extended"));
    assert!(status(&f, &["list", "md5", "miri-routine"]).contains("md5-bulk:0"));
    assert!(status(&f, &["show", "md5", "answers"]).contains("\"CASE\": \"0\""));
    f.ok(&["run", "md5", "answers"]);
    f.ok(&["run", "md5", "answers"]);
    let attempts = f.state()["attempts"].clone();
    let text = status(&f, &["md5"]);
    assert!(text.contains("Configurations: 2 | Current passes: 1/2"));
    assert!(text.contains(f.attempt("md5/answers")["ended"].as_str().unwrap()));
    assert_eq!(f.state()["attempts"], attempts);
    assert_eq!(
        fs::read_to_string(f.root().join("executed"))
            .unwrap()
            .lines()
            .count(),
        2
    );
    let before = fs::read(f.root().join("verification/results.json")).unwrap();
    assert_eq!(status(&f, &["md5"]), text);
    assert_eq!(
        fs::read(f.root().join("verification/results.json")).unwrap(),
        before
    );
}

#[test]
fn mixed_failures_and_outdated_inputs_never_become_a_group_pass() {
    let f = grouped_fixture();
    f.ok(&["run", "md5", "answers"]);
    let success = f.attempt("md5/answers")["ended"]
        .as_str()
        .unwrap()
        .to_string();
    f.write("mode", "fail");
    assert!(!f.run(&["run", "md5", "boundaries"]).status.success());
    let failed = f.attempt("md5/boundaries")["ended"]
        .as_str()
        .unwrap()
        .to_string();
    let text = status(&f, &["md5", "--category", "miri-routine"]);
    assert!(text.contains("Current passes: 1/2 | failed: 1; passed: 1"));
    assert!(text.contains(&format!("Latest execution activity (UTC): {failed}")));
    assert!(text.contains(&format!("Last successful execution (UTC): {success}")));
    let attempts = f.state()["attempts"].clone();
    f.write("md5/input", "changed");
    let text = status(&f, &["md5", "--category", "miri-routine"]);
    assert!(text.contains("Current passes: 0/2"));
    assert!(text.contains("Outdated (see show for changed inputs): 2"));
    assert_eq!(f.state()["attempts"], attempts);
    let details = status(&f, &["show", "md5", "answers"]);
    assert!(details.contains("md5/input"));
}
