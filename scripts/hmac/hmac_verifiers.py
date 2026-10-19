"""Pinned, bounded HMAC verifier execution; no ambient flag or leak waiver."""
import os
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "scripts/repository"))
import facade_cargo_environment as cargo_environment


def tool(identity):
    policy = tomllib.loads((ROOT / "assurance/policy.toml").read_text())
    matches = [row for row in policy["tools"] if row["id"] == identity]
    if len(matches) != 1:
        raise ValueError("missing/ambiguous verifier identity")
    return matches[0]


def environment(directory):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("CARGO_", "RUST", "BRYNJA_", "MIRI", "KANI", "ASAN_", "LSAN_", "UBSAN_"))}
    env["CARGO_HOME"] = os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))
    env["CARGO_TARGET_DIR"] = str(directory / "target")
    cargo_environment.check(ROOT, env)
    return env


def run(command, env, directory=ROOT):
    cargo_environment.check(directory, env)
    completed = subprocess.run(command, cwd=directory, env=env, text=True,
                               capture_output=True, timeout=300)
    if completed.returncode:
        raise RuntimeError("HMAC verifier failed:\n" + completed.stdout[-6000:] + completed.stderr[-6000:])
    return completed.stdout + completed.stderr
