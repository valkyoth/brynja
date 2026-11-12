#!/usr/bin/env python3
"""Bounded native or explicitly emulated AES round-candidate correctness only."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
MARKERS = (
    "AES_KERNEL_KAT_PASS: 128:568",
    "AES_KERNEL_KAT_PASS: 192:700",
    "AES_KERNEL_KAT_PASS: 256:810",
    "AES_KERNEL_ALIGNMENT_PASS: 768",
)


def validate_output(text):
    lines = text.splitlines()
    for marker in MARKERS:
        if lines.count(marker) != 1:
            raise ValueError(f"missing or repeated completion marker: {marker}")
    if text.count("test result: ok. 5 passed; 0 failed; 0 ignored;") != 1:
        raise ValueError("candidate test population incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", choices=("1.90.0", "1.99.1"), default="1.99.1")
    parser.add_argument("--qemu-aarch64", action="store_true",
                        help="Emulation only, never native hardware or timing qualification")
    args = parser.parse_args()
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN", "RUSTC_WRAPPER"):
        if os.environ.get(name):
            raise ValueError(f"remove ambient {name}")
    target_dir = ROOT / "target" / "aes-kernel-candidate"
    target_dir.mkdir(parents=True, exist_ok=True)
    # Retain failed and passing binaries/logs; never erase an earlier attempt.
    directory = Path(tempfile.mkdtemp(prefix="check-", dir=target_dir))
    print(f"Artifacts: {directory}", flush=True)
    binary = directory / "kernels"
    target = (["--target", "aarch64-unknown-linux-musl"] if args.qemu_aarch64 else [])
    compile_probe = ["rustc", f"+{args.toolchain}", "--edition=2024", "--crate-type=lib",
                     "--emit=obj", str(ROOT / "assurance/aes-kernel-candidate/compile.rs"),
                     *target]
    subprocess.run([*compile_probe, "-o", str(directory / "valid.o")],
                   cwd=ROOT, check=True, timeout=180)
    negative = subprocess.run([*compile_probe, "--cfg", "invalid_aes_schedule",
                               "-o", str(directory / "invalid.o")],
                              cwd=ROOT, check=False, timeout=180, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (directory / "invalid-schedule.log").write_text(negative.stdout)
    if (negative.returncode == 0 or "E0080" not in negative.stdout
            or "assertion failed: matches!(N, 11 | 13 | 15)" not in negative.stdout):
        raise ValueError("invalid schedule width did not fail at the expected constant assertion")
    print("AES kernel no_std/invalid-width compile controls PASS")
    command = ["rustc", f"+{args.toolchain}", "--edition=2024", "--test",
               str(ROOT / "assurance/aes-kernel-candidate/main.rs"),
               "-C", "opt-level=2", "-C", "overflow-checks=yes", "-o", str(binary)]
    if args.qemu_aarch64:
        command += ["--target", "aarch64-unknown-linux-musl", "-C", "linker=rust-lld"]
    subprocess.run(command, cwd=ROOT, check=True, timeout=180)
    runner = ["qemu-aarch64", "-cpu", "max"] if args.qemu_aarch64 else []
    result = subprocess.run([*runner, str(binary), "--nocapture", "--test-threads=1"],
                            cwd=ROOT, check=False, timeout=180, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (directory / "tests.log").write_text(result.stdout)
    print(result.stdout, end="")
    result.check_returncode()
    validate_output(result.stdout)
    mode = "QEMU AArch64 emulation" if args.qemu_aarch64 else "native host"
    print(f"AES kernel candidate PASS ({mode}, Rust {args.toolchain}); correctness only")
    print("No public acceleration, admission, lifecycle or side-channel qualification claimed.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        if isinstance(error, subprocess.CalledProcessError) and error.stdout:
            print(error.stdout, end="")
        print(f"AES kernel candidate FAIL: {error}")
        raise SystemExit(2) from error
