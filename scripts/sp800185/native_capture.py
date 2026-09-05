#!/usr/bin/env python3
"""Operator-reviewed native SP 800-185 reports, never backend admission."""

from __future__ import annotations

import json
import os
import platform
import re
from pathlib import Path

import execution_acceptance as acceptance

LANES = {
    "local-amd-x86_64": ("Linux", "x86_64", "AuthenticAMD"),
    "aws-intel-x86_64": ("Linux", "x86_64", "GenuineIntel"),
    "aws-aarch64": ("Linux", "aarch64", None),
    "apple-m2-aarch64": ("Darwin", "arm64", "Apple M2"),
    "riscv64-cloud": ("Linux", "riscv64", None),
}
TOOLCHAIN = "1.98.1"


def validate_host(lane: str, system: str, machine: str, identity: str) -> None:
    if lane not in LANES:
        raise acceptance.ExecutionError("unregistered capture lane")
    expected_os, expected_arch, vendor = LANES[lane]
    if (system, machine) != (expected_os, expected_arch):
        raise acceptance.ExecutionError("capture host does not match lane")
    if vendor is not None and vendor not in identity:
        raise acceptance.ExecutionError("capture CPU does not match lane")


def check_environment(environment: dict[str, str]) -> None:
    # Do not accept evidence-only cfgs, cross runners or inherited compiler flags.
    exact = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER",
             "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTFLAGS"}
    if any(value and (key in exact or key.startswith("CARGO_TARGET_"))
           for key, value in environment.items()):
        raise acceptance.ExecutionError("native capture requires default compiler and target settings")


def clean_commit() -> str:
    if acceptance.execute(["git", "status", "--porcelain=v1", "--untracked-files=all"]).strip():
        raise acceptance.ExecutionError("native capture requires a clean worktree")
    commit = acceptance.execute(["git", "rev-parse", "HEAD"]).strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise acceptance.ExecutionError("invalid source commit")
    return commit


def capture(lane: str, destination: Path) -> None:
    os.chdir(acceptance.ROOT)
    check_environment(dict(os.environ))
    system, machine = platform.system(), platform.machine()
    if lane not in LANES:
        raise acceptance.ExecutionError("unregistered capture lane")
    identity = (
        acceptance.execute(["sysctl", "-n", "machdep.cpu.brand_string"]).strip()
        if system == "Darwin" else Path("/proc/cpuinfo").read_text(encoding="utf-8")
    )
    validate_host(lane, system, machine, identity)
    # Only archive known vendor labels, never hostname, username, CPU serial or IP.
    vendor = LANES[lane][2] or "operator-attested ARM/RISC-V host"
    commit = clean_commit()
    acceptance.validate()
    compiler = acceptance.execute(["rustc", f"+{TOOLCHAIN}", "--version"]).strip()
    if not compiler.startswith(f"rustc {TOOLCHAIN} "):
        raise acceptance.ExecutionError("wrong release compiler")
    if destination.exists() or destination.is_symlink():
        raise acceptance.ExecutionError("refusing to overwrite an evidence report")
    commands = {
        "execution": ["cargo", f"+{TOOLCHAIN}", "run", "--quiet", "--locked", "--offline",
                      "--release", "--manifest-path", "assurance/sp800185-final/Cargo.toml",
                      "--", "--benchmark"],
        "worker_faults": ["cargo", f"+{TOOLCHAIN}", "test", "--locked", "--offline",
                          "-p", "brynja-hash-parallel-std", "--lib"],
        "candidate_kat": ["cargo", f"+{TOOLCHAIN}", "test", "--locked", "--offline",
                          "-p", "brynja-crypto-cpu", "--lib", "keccak"],
        "tag_timing": ["cargo", f"+{TOOLCHAIN}", "run", "--quiet", "--locked", "--offline",
                       "--release", "--manifest-path", "assurance/kmac-timing/Cargo.toml"],
    }
    outputs = {name: acceptance.execute(command, 900) for name, command in commands.items()}
    acceptance.check_report(outputs["execution"])
    if outputs["execution"].count("benchmark: ") != 12:
        raise acceptance.ExecutionError("incomplete performance observations")
    for name in ("worker_faults", "candidate_kat"):
        if "test result: ok." not in outputs[name] or "running 0 tests" in outputs[name]:
            raise acceptance.ExecutionError(f"missing native test execution: {name}")
    if "KMAC tag comparison timing:" not in outputs["tag_timing"]:
        raise acceptance.ExecutionError("missing tag-comparison timing observation")
    if clean_commit() != commit:
        raise acceptance.ExecutionError("repository changed during capture")
    report = {
        "schema": 1, "milestone": "0.24.17", "commit": commit,
        "lane": lane, "system": system, "architecture": machine, "vendor": vendor,
        "compiler": compiler, "native_operator_attestation_required": True,
        "status": "PENDING_REVIEW", "admitted_keccak_backends": [],
        "claim": "portable execution only; no independent review or FIPS validation",
        "commands": commands, "stdout": outputs,
        "stdout_sha256": {name: acceptance.digest(output) for name, output in outputs.items()},
        "policy_sha256": acceptance.digest(acceptance.read(acceptance.ROOT, acceptance.HASHES)),
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
