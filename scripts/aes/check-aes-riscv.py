#!/usr/bin/env python3
"""Explicit RV64 scalar AES candidate checks under QEMU, never native qualification."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
TARGET = "riscv64gc-unknown-linux-gnu"
SPEC = importlib.util.spec_from_file_location("aes_static_runner", Path(__file__).with_name("check-aes-static.py"))
STATIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATIC)
PHASES = {
    "candidate": (True, "+zkne,+zknd", "max,zknh=false"),
    "unadmitted": (False, "+zkne,+zknd", "max,zknh=false"),
    "no-encrypt": (True, "-zkne,+zknd", "max,zknh=false,zkne=false"),
    "no-decrypt": (True, "+zkne,-zknd", "max,zknh=false,zknd=false"),
}
REJECT_ENV = (
    "PYTHONOPTIMIZE", "PYTHONPATH", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
    "RUSTDOCFLAGS", "RUSTUP_TOOLCHAIN", "RUSTC", "RUSTDOC", "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTFLAGS",
    "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUSTFLAGS",
    "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER",
    "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER",
)
BOUNDARY_MARKERS = tuple(
    f"AES_RISCV_BOUNDARIES: {bits} 256 alignment pairs; both owners; both directions; public output; canaries; clear/drop"
    for bits in (128, 192, 256)
)


def phase_config(name):
    evidence, features, cpu = PHASES[name]
    flags = (["--cfg", "brynja_cpu_evidence"] if evidence else [])
    return flags + ["-C", "target-feature=" + features], cpu


def run(command, env, artifacts, name):
    # Keep reproducible argv/cwd and only non-secret build settings, never a
    # dump of the caller's environment. STATIC.run enforces exit status/timeout.
    settings = {key: env[key] for key in (
        "RUSTFLAGS", "CARGO_TARGET_DIR", "RUSTUP_AUTO_INSTALL",
        "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER",
        "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER") if key in env}
    (artifacts / (name + "-command.json")).write_text(json.dumps(
        {"command": command, "cwd": str(ROOT), "environment": settings}, indent=2) + "\n")
    return STATIC.run(command, env, artifacts, name)


def platform_config():
    """Resolve a dedicated target runtime; never fall back to host execution."""
    qemu = shutil.which("qemu-riscv64")
    linker = shutil.which("riscv64-linux-gnu-gcc") or shutil.which("riscv64-suse-linux-gcc")
    if not qemu or not linker:
        raise ValueError("RV64 QEMU and a RISC-V GNU cross linker are required")
    sysroot = subprocess.check_output([linker, "--print-sysroot"], text=True).strip()
    # Debian cross GCC may report /; its target runtime is in the triplet tree.
    if sysroot == "/" and Path("/usr/riscv64-linux-gnu").is_dir():
        sysroot = "/usr/riscv64-linux-gnu"
    if not sysroot or sysroot == "/" or not Path(sysroot).is_dir():
        raise ValueError("a dedicated RISC-V runtime sysroot is required")
    return qemu, linker, sysroot


def execution(qemu, sysroot, cpu="max,zknh=false"):
    return [qemu, "-cpu", cpu, "-L", sysroot, "-E",
            "LD_LIBRARY_PATH=/lib:/lib64:/lib64/lp64d:/usr/lib:/usr/lib64"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", choices=("1.90.0", "1.99.1"), default="1.99.1")
    args = parser.parse_args()
    for key in REJECT_ENV:
        if os.environ.get(key):
            raise ValueError(f"remove ambient {key}")
    qemu, linker, sysroot = platform_config()
    base = ROOT / "target/aes-riscv"
    base.mkdir(parents=True, exist_ok=True)
    artifacts = Path(tempfile.mkdtemp(prefix=args.toolchain + "-", dir=base))
    print(f"Artifacts: {artifacts}", flush=True)
    env = dict(os.environ, RUSTUP_AUTO_INSTALL="0")
    run([qemu, "--version"], env, artifacts, "qemu-version")
    run(["rustc", "+" + args.toolchain, "-vV"], env, artifacts, "compiler-version")
    for phase in PHASES:
        flags, cpu = phase_config(phase)
        env["RUSTFLAGS"] = shlex.join(flags)
        env["CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER"] = linker
        env["CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER"] = shlex.join(execution(qemu, sysroot, cpu))
        env["CARGO_TARGET_DIR"] = str(base / f"build-{args.toolchain}-{phase}")
        for profile in ("debug", "release"):
            cargo = ["cargo", "+" + args.toolchain, "test", "--locked", "--offline", "--target", TARGET]
            if profile == "release":
                cargo += ["--release"]
            harness = ["--", "--show-output", "--test-threads=1"]
            prefix = f"{phase}-{profile}"
            (artifacts / (prefix + "-config.txt")).write_text(
                f"target={TARGET}\nflags={env['RUSTFLAGS']}\nlinker={linker}\nsysroot={sysroot}\n"
                f"runner={env['CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER']}\n")
            output = run([*cargo, "-p", "brynja-crypto-cpu", "--features", "aes-runtime-execution",
                                 "--lib", "aes::tests::", *harness], env, artifacts, prefix + "-authority")
            STATIC.validate_tests(output, 9 if phase == "candidate" else 6,
                                  (STATIC.STARTUP_MARKER,) if phase == "candidate" else ())
            output = run([*cargo, "-p", "brynja-crypto", "--no-default-features",
                                 "--features", "aes-static-execution", "--test", "aes_execution",
                                 *harness], env, artifacts, prefix + "-owners")
            STATIC.validate_tests(output, 13 if phase == "candidate" else 1,
                                  STATIC.KAT_MARKERS if phase == "candidate" else ())
            if phase == "candidate":
                output = run([*cargo, "-p", "brynja-crypto", "--no-default-features",
                                     "--features", "aes-static-execution", "--lib",
                                     "aes::tests::execution::", *harness], env, artifacts, prefix + "-faults")
                STATIC.validate_tests(output, 4, STATIC.FAULT_MARKERS)
                output = run([*cargo, "-p", "brynja-crypto", "--no-default-features",
                                     "--features", "aes-static-execution", "--test", "aes_riscv",
                                     *harness], env, artifacts, prefix + "-boundaries")
                STATIC.validate_tests(output, 3, BOUNDARY_MARKERS)
            output = run([*cargo, "-p", "brynja-crypto-cpu-std", "--features",
                                 "aes-runtime-execution", "--lib", "aes::tests::",
                                 *harness], env, artifacts, prefix + "-hosted")
            STATIC.validate_tests(output, 6)
            print(f"AES_RISCV_PHASE_PASS: {phase} {profile}", flush=True)
    print(f"AES_RISCV_QEMU_PASS: {args.toolchain}; 148 tests; evidence-only candidate")
    print("QEMU functional coverage only; no native performance, timing or deployment admission.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"AES RISC-V FAIL: {error}")
        raise SystemExit(2) from error
