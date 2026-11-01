mod common;
use common::Fixture;
use std::fs;

fn registry(f: &Fixture, change: impl FnOnce(String) -> String) {
    let raw = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    f.write("verification/checks.toml", &change(raw));
}

#[test]
fn stdin_is_executed_fingerprinted_and_preserves_other_results() {
    let f = Fixture::new();
    f.ok(&["run", "aes", "answers"]);
    let previous = f.attempt("aes/answers");
    f.write("vectors", "expected input\n");
    f.write("stdin.py", "import sys\nassert sys.stdin.read() == 'expected input\\n'\nprint('PASS\\ntest result: ok. 1 passed; 0 failed; 0 ignored;')\n");
    registry(&f, |s| {
        s.replace("id='boundaries'", "id='boundaries'\nstdin='vectors'")
            .replace(
                "command=['python3','check.py','md5/boundaries']",
                "command=['python3','stdin.py']",
            )
    });
    f.ok(&["run", "md5", "boundaries"]);
    let attempt = f.attempt("md5/boundaries");
    assert_eq!(attempt["stdin"], "vectors");
    assert!(attempt["source"].as_str().unwrap().contains("working tree"));
    f.write("vectors", "changed\n");
    f.ok(&["md5"]);
    assert!(
        f.view("md5/boundaries")["freshness"]
            .as_str()
            .unwrap()
            .contains("stdin: vectors")
    );
    assert_eq!(attempt, f.attempt("md5/boundaries"));
    assert_eq!(previous, f.attempt("aes/answers"));
}

#[test]
fn missing_unsafe_and_generated_stdin_never_executes() {
    for path in [
        "missing",
        "../escape",
        "verification/results.json",
        "docs/VERIFICATION_RESULTS.md",
    ] {
        let f = Fixture::new();
        registry(&f, |s| {
            s.replace(
                "id='boundaries'",
                &format!("id='boundaries'\nstdin='{path}'"),
            )
        });
        assert!(!f.run(&["run", "md5", "boundaries"]).status.success());
        assert!(!f.root().join("executed").exists());
    }
}

#[test]
fn compatibility_ignored_tests_require_opt_in_and_real_executed_tests() {
    for (summary, allowed, passes) in [
        ("1 passed; 0 failed; 2 ignored;", false, false),
        ("1 passed; 0 failed; 2 ignored;", true, true),
        ("0 passed; 0 failed; 2 ignored;", true, false),
        ("1 passed; 1 failed; 2 ignored;", true, false),
        ("1 passed; 0 failed; unknown ignored;", true, false),
    ] {
        let f = Fixture::new();
        f.write(
            "check.py",
            &format!("print('PASS\\ntest result: ok. {summary}')\n"),
        );
        if allowed {
            registry(&f, |s| {
                s.replace("minimum_tests=1", "minimum_tests=1\nallow_ignored=true")
            });
        }
        assert_eq!(f.run(&["run", "md5", "answers"]).status.success(), passes);
        assert_eq!(
            f.attempt("md5/answers")["outcome"],
            if passes { "passed" } else { "failed" }
        );
    }
}
