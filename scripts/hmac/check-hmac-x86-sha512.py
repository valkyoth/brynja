#!/usr/bin/env python3
"""Explicit HMAC SHA512 SDE execution; never native or timing qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess

import hmac_verifiers as verifier

ROOT = verifier.ROOT
TARGET = "x86_64-unknown-linux-gnu"
FLAGS = "-C target-feature=+sha512,+avx2,+avx"
CASES = (
    ("brynja-mac-hmac", "hardened-execution", ("--test", "execution"), "execution", "native_sha512"),
    ("brynja-crypto-cpu-std", "strict-hmac-acceleration", ("--lib",), "brynja_crypto_cpu_std",
     "strict_hmac::compiled::tests::native::sha512_route"),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def snapshot():
    # A conservative source inventory, NOT a rerun selector or approved receipt.
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--",
                                     "crates", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "scripts/hmac",
                                     "scripts/repository/facade_cargo_environment.py", "assurance/hmac-faults/host_probe.rs"], cwd=ROOT)
    files = sorted(set(names.decode().split("\0")) - {""})
    files += [str(Path(__file__).resolve().relative_to(ROOT))]
    return {name: sha((ROOT / name).read_bytes()) for name in sorted(set(files))
            if Path(name).suffix in (".rs", ".py", ".toml", ".lock")}


def run(command, env, records):
    verifier.cargo_environment.check(ROOT, env)
    print("RUN (SDE development): " + " ".join(map(str, command)), flush=True)
    result = subprocess.run(list(map(str, command)), cwd=ROOT, env=env, text=True,
                            capture_output=True, timeout=600)
    output = result.stdout + result.stderr
    if len(output.encode()) > 8 * 1024 * 1024:
        raise ValueError("oversized HMAC SDE command output")
    records.append({"command": list(map(str, command)), "exit_status": result.returncode,
                    "stdout": result.stdout, "stderr": result.stderr, "output_sha256": sha(output.encode())})
    if result.returncode:
        raise RuntimeError("HMAC SDE command failed:\n" + output[-8000:])
    return result.stdout


def executable(output, target, directory):
    artifacts = [row for row in map(json.loads, output.splitlines())
                 if row.get("reason") == "compiler-artifact" and row.get("executable")]
    if len(artifacts) != 1 or artifacts[0].get("target", {}).get("name") != target \
            or artifacts[0].get("profile", {}).get("test") is not True:
        raise ValueError("missing/ambiguous HMAC test executable")
    path = Path(artifacts[0]["executable"])
    if not path.is_absolute() or not path.resolve().is_relative_to(directory.resolve()) \
            or path.is_symlink() or not path.is_file():
        raise ValueError("HMAC test executable escaped private build")
    return path


def population(output, name):
    summaries = re.findall(r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
                           r"(\d+) measured; (\d+) filtered out;", output, re.M)
    tests = re.findall(r"^test (\S+) \.\.\. (\S+)$", output, re.M)
    if len(summaries) != 1 or summaries[0][:5] != ("ok", "1", "0", "0", "0") \
            or tests != [(name, "ok")]:
        raise ValueError("HMAC SDE exact test population changed")


def execute(sde, toolchains, directory, records):
    env = verifier.environment(directory)
    version = run([sde, "-version"], env, records)
    probe = directory / "generic-sha512-probe"
    run(["rustc", "+1.99.1", "--edition=2024", "-C", "target-cpu=generic",
         ROOT / "assurance/hmac-faults/host_probe.rs", "-o", probe], env, records)
    if run([sde, "-arl", "--", probe, "sha512"], env, records).splitlines() != ["HMAC_HOST_FEATURES: sha512"]:
        raise ValueError("SDE model does not report the required SHA512 bundle")
    results = []
    for toolchain in toolchains:
        identity = run(["rustc", "+" + toolchain, "-vV"], env, records)
        mode = dict(env, RUSTFLAGS=FLAGS, CARGO_TARGET_DIR=str(directory / toolchain))
        for profile in ([], ["--release"]):
            for package, features, selector, target, test in CASES:
                build = ["cargo", "+" + toolchain, "test", "--locked", "--offline", "--target", TARGET,
                         "-p", package, "--no-default-features", "--features", features,
                         *selector, *profile, "--no-run", "--message-format=json"]
                binary = executable(run(build, mode, records), target, directory)
                digest = sha(binary.read_bytes())
                # Execute the exact artifact directly: no ambient Cargo runner,
                # ignored-test skip, native fallback, or compilation-only PASS.
                command = [sde, "-arl", "--", binary, test, "--exact", "--ignored", "--test-threads=1"]
                population(run(command, mode, records), test)
                if sha(binary.read_bytes()) != digest:
                    raise ValueError("test executable changed during SDE execution")
                results.append({"toolchain": toolchain, "compiler": identity, "package": package,
                                "profile": "release" if profile else "debug", "test": test,
                                "identities": 6, "binary_sha256": digest})
    return {"emulator_version": version, "results": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sde", required=True, type=Path, help="previously licensed Intel SDE executable")
    parser.add_argument("--output", required=True, type=Path, help="new local development observation, not a receipt")
    parser.add_argument("--toolchain", action="append", choices=("1.90.0", "1.99.1"))
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("requires Linux x86-64; emulation does not qualify another native platform")
    sde = args.sde.resolve(strict=True)
    if not sde.is_file() or not os.access(sde, os.X_OK):
        parser.error("--sde must be an executable file")
    toolchains = args.toolchain or ["1.90.0", "1.99.1"]
    if len(toolchains) != len(set(toolchains)):
        parser.error("duplicate compiler")
    document = {"schema": 1, "kind": "author-operated-hmac-sde-development", "status": "failed",
                "claim": "emulated functional execution only; NOT native, timing or release qualification",
                "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "tracked_diff_sha256": sha(subprocess.check_output(["git", "diff", "HEAD", "--"], cwd=ROOT)),
                "sources": snapshot(), "target": TARGET, "rustflags": FLAGS,
                "sde_sha256": sha(sde.read_bytes()), "commands": []}
    # Reserve the output before any execution. Preserve failure diagnostics and
    # never replace a previous failed observation with a passing retry.
    with args.output.open("x") as output:
        try:
            with verifier.cargo_environment.private_directory(ROOT) as temporary:
                document.update(execute(sde, toolchains, Path(temporary), document["commands"]))
            if snapshot() != document["sources"] or sha(sde.read_bytes()) != document["sde_sha256"]:
                raise ValueError("HMAC source/emulator changed during observation")
            document["status"] = "pass"
        except Exception as error:
            document["error"] = str(error)
            raise
        finally:
            json.dump(document, output, indent=2)
            output.write("\n")
    print("HMAC dedicated x86 SHA512: emulated functional PASS; NOT native qualification", flush=True)


if __name__ == "__main__":
    main()
