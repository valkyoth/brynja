#!/usr/bin/env python3
"""Explicit static AES development correctness/lifecycle; never a timing claim."""
import argparse
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
KAT_MARKERS = tuple(f"AES_EXECUTION_KAT_PASS: {width}:{count}"
                    for width, count in ((128, 568), (192, 700), (256, 810)))
STARTUP_MARKER = "AES_EXPANSION_STARTUP_PASS: 624 mismatches rejected"
FAULT_MARKERS = ("AES_EXECUTION_EXPANSION_OPERATION_FAULT_PASS: 36",
                 "AES_EXECUTION_EXPANSION_CONSTRUCTOR_FAULT_PASS: 12",
                 "AES_EXECUTION_EXPANSION_CACHED_PASS: 3",
                 "AES_EXECUTION_EXPANSION_REVOKE_PASS: 12")


def validate_tests(output, count, markers=()):
    summaries = re.findall(r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;", output, re.M)
    if summaries != [("ok", str(count), "0", "0")]:
        raise ValueError(f"expected exactly {count} passing tests: {summaries}")
    for marker in markers:
        if output.splitlines().count(marker) != 1:
            raise ValueError(f"missing or repeated marker: {marker}")


def run(command, env, artifacts, name):
    result = subprocess.run(command, cwd=ROOT, env=env, check=False, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    (artifacts / f"{name}.log").write_text(result.stdout)
    print(result.stdout, end="", flush=True)
    result.check_returncode()
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", choices=("1.90.0", "1.99.1"), default="1.99.1")
    parser.add_argument("--mode", choices=("native", "baseline", "arm-qemu"), default="native")
    args = parser.parse_args()
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN", "RUSTC",
                 "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET"):
        if os.environ.get(name):
            raise ValueError(f"remove ambient {name}")
    machine = platform.machine().lower()
    if machine not in ("x86_64", "amd64", "aarch64", "arm64"):
        raise ValueError("unsupported test host")
    base = ROOT / "target/aes-static"
    base.mkdir(parents=True, exist_ok=True)
    artifacts = Path(tempfile.mkdtemp(prefix=f"{args.mode}-{args.toolchain}-", dir=base))
    print(f"Artifacts: {artifacts}", flush=True)
    env = dict(os.environ, RUSTUP_AUTO_INSTALL="0", CARGO_TARGET_DIR=str(base / f"build-{args.mode}-{args.toolchain}"))
    target = []
    if args.mode == "arm-qemu":
        target = ["--target", "aarch64-unknown-linux-musl"]
        env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"] = "rust-lld"
        env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER"] = "qemu-aarch64 -cpu max"
    if args.mode != "baseline":
        probe = artifacts / "probe"
        command = ["rustc", f"+{args.toolchain}", "--edition=2024",
                   str(ROOT / "assurance/aes-kernel-candidate/probe.rs"), "-o", str(probe), *target]
        if target:
            command += ["-C", "linker=rust-lld"]
        run(command, env, artifacts, "probe-compile")
        runner = ["qemu-aarch64", "-cpu", "max"] if target else []
        observed = run([*runner, str(probe)], env, artifacts, "probe")
        if observed.splitlines() != ["AES_STATIC_HOST_BUNDLE_PASS"]:
            raise ValueError("host probe did not establish exact bundle")
    flags = "-Ctarget-feature=-aes" if args.mode == "baseline" else (
        "-Ctarget-feature=+aes,+neon" if target or machine in ("aarch64", "arm64")
        else "-Ctarget-feature=+aes,+sse2")
    env["RUSTFLAGS"] = flags
    cargo = ["cargo", f"+{args.toolchain}", "test", "--locked", "--offline", *target]
    # Captured, ordered output prevents libtest progress from interleaving with
    # completion markers. Never relax exact-line validation to accept that mix.
    test_output = ["--", "--show-output", "--test-threads=1"]
    control = run([*cargo, "-p", "brynja-crypto-cpu", "--features", "aes-static-execution",
                   "--lib", "aes::tests::", *test_output], env, artifacts, "authority")
    validate_tests(control, 6 if args.mode == "baseline" else 9,
                   () if args.mode == "baseline" else (STARTUP_MARKER,))
    owners = run([*cargo, "-p", "brynja-crypto", "--no-default-features", "--features", "aes-static-execution",
                  "--test", "aes_execution", *test_output], env, artifacts, "owners")
    validate_tests(owners, 1 if args.mode == "baseline" else 13,
                   () if args.mode == "baseline" else KAT_MARKERS)
    if args.mode != "baseline":
        faults = run([*cargo, "-p", "brynja-crypto", "--no-default-features", "--features", "aes-static-execution",
                      "--lib", "aes::tests::execution::", *test_output], env, artifacts, "faults")
        validate_tests(faults, 4, FAULT_MARKERS)
    print(f"AES_STATIC_PASS: {args.mode} {args.toolchain}")
    print("Development correctness/lifecycle only; no timing, emitted-code or physical-fault qualification.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"AES static FAIL: {error}")
        raise SystemExit(2) from error
