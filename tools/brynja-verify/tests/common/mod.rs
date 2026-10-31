use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::TempDir;

pub struct Fixture {
    dir: TempDir,
}
impl Fixture {
    pub fn new() -> Self {
        let s = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        s.write("md5/input", "md5 original");
        s.write("aes/input", "aes original");
        s.write("shared/input", "shared original");
        s.write(
            "check.py",
            r#"import pathlib, sys, time
mode = pathlib.Path('mode').read_text() if pathlib.Path('mode').exists() else 'pass'
with pathlib.Path('executed').open('a') as f: f.write(sys.argv[1] + '\n')
if mode == 'slow': time.sleep(20)
if mode == 'edit': pathlib.Path('md5/input').write_text('changed during execution')
if mode == 'fail': print('FAIL'); sys.exit(1)
if mode == 'zero': print('test result: ok. 0 passed; 0 failed; 0 ignored;'); sys.exit(0)
if mode == 'skip': print('PASS\ntest result: ok. 0 passed; 0 failed; 1 ignored;'); sys.exit(0)
print('PASS\ntest result: ok. 1 passed; 0 failed; 0 ignored;')
"#,
        );
        let mut registry = String::from(
            "schema=1\nexecution_semantics=1\n[groups.md5]\npaths=['md5','check.py']\n[groups.aes]\npaths=['aes','check.py']\n[groups.shared]\npaths=['shared']\n",
        );
        for (component, id) in [
            ("md5", "answers"),
            ("md5", "boundaries"),
            ("aes", "answers"),
        ] {
            registry += &format!(
                r#"
[[checks]]
component='{component}'
id='{id}'
name='Readable {id}'
establishes='Fake fixture only'
command=['python3','check.py','{component}/{id}']
cwd='.'
inputs=['{component}','shared']
timeout_seconds=2
[checks.success]
contains=['PASS']
minimum_tests=1
"#
            );
        }
        s.write("verification/checks.toml", &registry);
        s.git(&["init", "-q"]);
        s.git(&["config", "user.name", "Fixture"]);
        s.git(&["config", "user.email", "fixture@example.invalid"]);
        s.git(&["config", "commit.gpgsign", "false"]);
        s.git(&["add", "."]);
        s.git(&["commit", "-qm", "initial"]);
        s
    }
    pub fn root(&self) -> &Path {
        self.dir.path()
    }
    pub fn write(&self, name: &str, value: &str) {
        let p = self.root().join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, value).unwrap();
    }
    pub fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(self.root())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    pub fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_brynja-verify"))
            .arg("--root")
            .arg(self.root())
            .args(args)
            .output()
            .unwrap()
    }
    pub fn ok(&self, args: &[&str]) {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    pub fn state(&self) -> Value {
        serde_json::from_slice(&fs::read(self.root().join("verification/results.json")).unwrap())
            .unwrap()
    }
    pub fn view(&self, key: &str) -> Value {
        self.state()["views"][key].clone()
    }
    pub fn attempt(&self, key: &str) -> Value {
        self.state()["attempts"][key]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .clone()
    }
}
