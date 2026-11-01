mod common;
use common::Fixture;
use std::fs;

fn fixture(pattern: &str) -> Fixture {
    let f = Fixture::new();
    let raw = fs::read_to_string(f.root().join("verification/checks.toml")).unwrap();
    f.write(
        "verification/checks.toml",
        &raw.replace(
            "[groups.md5]",
            &format!("[groups.md5]\npatterns=['{pattern}']"),
        ),
    );
    f
}

#[test]
fn pattern_changes_only_invalidate_their_dependents_and_never_execute_on_scan() {
    let f = fixture("crates/*/Cargo.toml");
    f.write("crates/md5/Cargo.toml", "one");
    f.ok(&["run", "md5", "answers"]);
    f.ok(&["run", "aes", "answers"]);
    let tested = f.attempt("md5/answers");
    let executions = fs::read(f.root().join("executed")).unwrap();
    f.write("crates/aes/src/lib.rs", "unrelated source");
    f.write("crates/md5/nested/Cargo.toml", "wrong depth");
    f.write("crates/.runner/Cargo.toml", "excluded output");
    f.ok(&["full-check"]);
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    for mutation in ["add", "edit", "rename", "delete"] {
        match mutation {
            "add" => f.write("crates/new/Cargo.toml", "new"),
            "edit" => f.write("crates/md5/Cargo.toml", "changed"),
            "rename" => {
                fs::rename(f.root().join("crates/md5"), f.root().join("crates/renamed")).unwrap()
            }
            _ => fs::remove_file(f.root().join("crates/md5/Cargo.toml")).unwrap(),
        }
        f.ok(&["full-check"]);
        assert_ne!(
            f.view("md5/answers")["freshness"],
            "Up to date",
            "{mutation}"
        );
        assert_eq!(f.view("aes/answers")["freshness"], "Up to date");
        if mutation == "rename" {
            fs::rename(f.root().join("crates/renamed"), f.root().join("crates/md5")).unwrap();
        }
        if mutation == "add" {
            fs::remove_file(f.root().join("crates/new/Cargo.toml")).unwrap();
        }
        f.write("crates/md5/Cargo.toml", "one");
        f.ok(&["md5"]);
        assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    }
    assert_eq!(f.attempt("md5/answers"), tested);
    assert_eq!(fs::read(f.root().join("executed")).unwrap(), executions);
    f.git(&["add", "."]);
    f.git(&["commit", "-qm", "same tested inputs"]);
    f.ok(&["md5"]);
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    assert_eq!(f.attempt("md5/answers"), tested);
    // A subsequent explicit fake execution at the committed inputs must be
    // identified as clean HEAD: exercise historical pattern resolution too.
    f.ok(&["run", "md5", "answers"]);
    assert!(
        !f.attempt("md5/answers")["source"]
            .as_str()
            .unwrap()
            .contains("working tree")
    );
}

#[test]
fn empty_matches_are_recorded_and_unsupported_patterns_fail_closed() {
    let f = fixture("scripts/*sha256*batch*.py");
    f.ok(&["run", "md5", "answers"]);
    f.write("scripts/sha512-batch.py", "unrelated");
    f.ok(&["md5"]);
    assert_eq!(f.view("md5/answers")["freshness"], "Up to date");
    f.write("scripts/check-sha256-batch.py", "relevant");
    f.ok(&["md5"]);
    assert_ne!(f.view("md5/answers")["freshness"], "Up to date");
    for pattern in [
        "*/*",
        "../*.rs",
        "crates/**/Cargo.toml",
        "crates/?/Cargo.toml",
        "crates/[a]/Cargo.toml",
        "crates//*.rs",
        "target/*.rs",
    ] {
        let bad = fixture(pattern);
        assert!(!bad.run(&["full-check"]).status.success(), "{pattern}");
        assert!(!bad.root().join("executed").exists());
    }
}

#[cfg(unix)]
#[test]
fn matching_symlinks_and_directories_cannot_be_current_passes() {
    use std::os::unix::fs::symlink;
    for parent in [false, true] {
        let f = fixture("crates/*/Cargo.toml");
        f.ok(&["run", "md5", "answers"]);
        f.write("external/Cargo.toml", "outside selection");
        if parent {
            fs::create_dir_all(f.root().join("crates")).unwrap();
            symlink(f.root().join("external"), f.root().join("crates/link")).unwrap();
        } else {
            fs::create_dir_all(f.root().join("crates/leaf")).unwrap();
            symlink(
                f.root().join("external/Cargo.toml"),
                f.root().join("crates/leaf/Cargo.toml"),
            )
            .unwrap();
        }
        f.ok(&["md5"]);
        assert_ne!(f.view("md5/answers")["freshness"], "Up to date");
        assert!(!f.run(&["run", "md5", "answers"]).status.success());
    }
    let f = fixture("crates/*/Cargo.toml");
    f.ok(&["run", "md5", "answers"]);
    fs::create_dir_all(f.root().join("crates/leaf/Cargo.toml")).unwrap();
    f.ok(&["md5"]);
    assert_ne!(f.view("md5/answers")["freshness"], "Up to date");
}
