mod common;
use common::Fixture;
use std::fs;

fn configure(f: &Fixture, optional: bool, extra: &str) {
    let raw = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    let path = format!(
        "{}:{}",
        f.root().join("bin").display(),
        std::env::var("PATH").unwrap()
    );
    f.write("verification/checks.toml", &raw.replace("[groups.md5]", &format!(
        "[groups.md5]\ntools=[{{program='brynja-fixture-demangler', optional={optional}{extra}}}]"))
        .replace("cwd='.'", &format!("cwd='.'\nenvironment={{PATH={path:?}}}")));
}

#[test]
fn optional_path_tools_track_absence_content_and_removal_without_execution() {
    let f = Fixture::new();
    configure(&f, true, "");
    f.ok(&["run", "md5", "answers"]);
    let original = f.attempt("md5/answers");
    f.write("bin/brynja-fixture-demangler", "not executed during scan\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.ok(&["md5"]);
        assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
        fs::set_permissions(
            f.root().join("bin/brynja-fixture-demangler"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    f.ok(&["md5"]);
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("tool brynja-fixture-demangler")
    );
    assert_eq!(original, f.attempt("md5/answers"));
    f.ok(&["run", "md5", "answers"]);
    f.write("bin/brynja-fixture-demangler", "changed tool contents\n");
    f.ok(&["md5"]);
    assert!(
        f.view("md5/answers")["freshness"]
            .as_str()
            .unwrap()
            .contains("tool brynja-fixture-demangler")
    );
    f.ok(&["run", "md5", "answers"]);
    fs::remove_file(f.root().join("bin/brynja-fixture-demangler")).unwrap();
    f.ok(&["md5"]);
    // Returning to the originally tested absence can reuse that execution;
    // it must not pretend the newer, tool-present attempt tested this state.
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    assert_eq!(f.view("md5/answers")["performed_at"], original["ended"]);
    assert!(
        f.view("md5/answers")["result"]
            .as_str()
            .unwrap()
            .contains("matching-input history")
    );
}

#[test]
fn required_tools_and_optional_toolchain_overrides_still_fail_closed() {
    for (optional, extra) in [(false, ""), (true, ", toolchain='1.99.1'")] {
        let f = Fixture::new();
        configure(&f, optional, extra);
        assert!(!f.run(&["run", "md5", "answers"]).status.success());
        assert!(!f.root().join("executed").exists());
    }
}
