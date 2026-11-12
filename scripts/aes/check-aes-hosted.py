#!/usr/bin/env python3
"""Baseline-compiled hosted AES selection and downstream clearing owners."""
import argparse
import importlib.util
import os
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("static_runner", Path(__file__).with_name("check-aes-static.py"))
STATIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATIC)
MARKERS = tuple(f"AES_HOSTED_KAT_PASS: {bits}:{count}" for bits, count in ((128, 568), (192, 700), (256, 810)))


def validate(output, accelerated):
    expected = (*MARKERS, "AES_HOSTED_ACCELERATED_PASS") if accelerated else ("AES_HOSTED_UNAVAILABLE_PASS",)
    all_markers = (*MARKERS, "AES_HOSTED_ACCELERATED_PASS", "AES_HOSTED_UNAVAILABLE_PASS")
    lines = output.splitlines()
    for marker in all_markers:
        if lines.count(marker) != int(marker in expected):
            raise ValueError(f"missing, repeated or wrong-route marker: {marker}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", choices=("1.90.0", "1.99.1"), default="1.99.1")
    parser.add_argument("--qemu-aarch64", action="store_true")
    args = parser.parse_args()
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN", "RUSTC",
                 "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET"):
        if os.environ.get(name):
            raise ValueError(f"remove ambient {name}")
    machine = platform.machine().lower()
    if machine not in ("x86_64", "amd64", "aarch64", "arm64"):
        raise ValueError("unsupported test host")
    accelerated = args.qemu_aarch64 or (machine in ("aarch64", "arm64") and platform.system() in ("Linux", "Darwin"))
    mode = "arm-qemu" if args.qemu_aarch64 else "native"
    base = ROOT / "target/aes-hosted"
    base.mkdir(parents=True, exist_ok=True)
    artifacts = Path(tempfile.mkdtemp(prefix=f"{mode}-{args.toolchain}-", dir=base))
    print(f"Artifacts: {artifacts}", flush=True)
    # Deliberately no positive global target-feature flags: detection must admit
    # the out-of-line kernel from a baseline executable.
    env = dict(os.environ, RUSTUP_AUTO_INSTALL="0", RUSTFLAGS="-Ctarget-feature=-aes",
               CARGO_TARGET_DIR=str(base / f"build-{mode}-{args.toolchain}"))
    target = []
    if args.qemu_aarch64:
        target = ["--target", "aarch64-unknown-linux-musl"]
        env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"] = "rust-lld"
        env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER"] = "qemu-aarch64 -cpu max"
    cargo = ["cargo", f"+{args.toolchain}"]
    output = STATIC.run([*cargo, "test", "--locked", "--offline", *target,
                         "-p", "brynja-crypto-cpu-std", "--features", "aes-runtime-execution",
                         "--lib", "aes::tests::", "--", "--nocapture"], env, artifacts, "selection")
    STATIC.validate_tests(output, 6)
    for profile in ([], ["--release"]):
        output = STATIC.run([*cargo, "run", "--locked", "--offline", *target, *profile,
                             "--manifest-path", "assurance/aes-hosted/Cargo.toml", "--",
                             "accelerated" if accelerated else "unavailable"], env, artifacts,
                            "consumer-release" if profile else "consumer-debug")
        validate(output, accelerated)
    print(f"AES_HOSTED_PASS: {mode} {args.toolchain}")
    print("Development selection/correctness only; no timing or final-linked qualification.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"AES hosted FAIL: {error}")
        raise SystemExit(2) from error
