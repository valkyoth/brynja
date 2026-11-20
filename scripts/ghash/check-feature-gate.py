"""Check raw GHASH visibility from isolated downstream dependency graphs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/hmac"))
from hmac_verifiers import environment


def check(compiler, package, route, work):
    manifest = work / "Cargo.toml"
    source = work / "probe.rs"
    source.write_text(f"#![no_std]\nuse dep::{route}ghash::Ghash;\n"
                      "pub fn probe(h: &[u8;16], w: &mut [u8;16]) { drop(Ghash::new(h, w, 0)); }\n")
    manifest.write_text(f"""[workspace]
[package]
name = "ghash-feature-probe"
version = "0.0.0"
edition = "2024"
publish = false
[lib]
path = "probe.rs"
[dependencies.dep]
package = "{package}"
path = {json.dumps(str(ROOT / "crates" / package))}
default-features = false
""")
    env = environment(work)
    cargo = ["cargo", "+" + compiler]
    subprocess.run([*cargo, "generate-lockfile", "--offline"], cwd=work, env=env, check=True)
    for features in (None, "dep/default", "dep/hazmat-aes-block", "dep/hazmat-ghash"):
        args = ["--features", features] if features else []
        result = subprocess.run([*cargo, "check", "--locked", "--offline", "--message-format=json",
                                 *args], cwd=work, env=env, text=True, capture_output=True, timeout=120)
        errors = [row["message"] for line in result.stdout.splitlines() if
                  (row := json.loads(line)).get("reason") == "compiler-message"
                  and row["message"]["level"] == "error"]
        if features == "dep/hazmat-ghash":
            ok = result.returncode == 0 and not errors
        else:
            ok = (result.returncode == 101 and len(errors) == 1 and
                  (errors[0].get("code") or {}).get("code") == "E0432" and
                  "ghash" in errors[0]["message"] and
                  any(s["is_primary"] and s["file_name"] == "probe.rs" for s in errors[0]["spans"]))
        if not ok:
            raise ValueError(f"{compiler}/{package}/{features}: unexpected feature-gate result")


if __name__ == "__main__":
    for compiler in ("1.90.0", "1.100.0"):
        for package, route in (("brynja", "crypto::"), ("brynja-crypto", "")):
            with tempfile.TemporaryDirectory() as folder:
                check(compiler, package, route, Path(folder))
    print("GHASH_FEATURE_GATE_COMPLETE: 16 direct/facade compiler checks")
