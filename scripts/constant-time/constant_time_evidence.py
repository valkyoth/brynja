#!/usr/bin/env python3
"""Validate the v0.12.0 constant-time evidence matrix and CI binding."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


COMPILERS = (
    "1.90.0",
    "1.91.0",
    "1.92.0",
    "1.93.0",
    "1.94.0",
    "1.95.0",
    "1.96.0",
    "1.96.1",
    "1.97.0",
    "1.97.1",
)
TARGETS = (
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-freebsd",
    "x86_64-apple-darwin",
    "aarch64-linux-android",
    "aarch64-apple-ios",
    "thumbv7em-none-eabi",
    "riscv32imac-unknown-none-elf",
    "x86_64-unknown-none",
)
LIMITS = (
    "source-and-emitted-code-evidence-is-not-a-proof",
    "no-microarchitectural-or-statistical-timing-claim",
    "no-cache-register-copy-or-physical-erasure-claim",
    "no-variable-length-operation-claim",
    "downstream-codegen-requires-separate-evidence",
    "declassification-before-final-decision-can-leak",
)


class EvidenceError(RuntimeError):
    """The constant-time evidence matrix or CI binding drifted."""


def fail(message: str) -> None:
    raise EvidenceError(message)


def validate(root: Path) -> None:
    with (root / "assurance/constant-time-matrix.toml").open("rb") as handle:
        matrix = tomllib.load(handle)
    if set(matrix) != {"schema", "claim", "coverage", "limits"}:
        fail("constant-time matrix sections drifted")
    if matrix["schema"] != {"version": 1, "milestone": "0.12.0"}:
        fail("constant-time matrix schema drifted")
    if matrix["claim"] != {
        "scope": "unsigned-words-and-compile-time-byte-arrays",
        "operations": [
            "equality",
            "conditional-select",
            "conditional-swap",
            "compiler-barrier",
        ],
        "array_witness_width": 32,
        "artifacts": ["source-policy", "llvm-ir", "assembly"],
        "declassification": "Choice::expose_public",
    }:
        fail("constant-time claim or artifact set drifted")
    coverage = matrix["coverage"]
    if (
        tuple(coverage.get("compilers", ())) != COMPILERS
        or coverage.get("compiler_target") != "x86_64-unknown-linux-gnu"
        or coverage.get("target_compiler") != "1.97.1"
        or tuple(coverage.get("targets", ())) != TARGETS
    ):
        fail("constant-time compiler or target coverage drifted")
    if tuple(matrix["limits"].get("values", ())) != LIMITS:
        fail("constant-time evidence limits drifted")

    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    compiler_step = (
        'run: scripts/constant-time/check-constant-time-codegen.sh "${{ matrix.rust }}" '
        "x86_64-unknown-linux-gnu"
    )
    target_step = (
        'run: scripts/constant-time/check-constant-time-codegen.sh 1.97.1 "${{ matrix.target }}"'
    )
    if compiler_step not in workflow or target_step not in workflow:
        fail("CI does not execute both constant-time evidence dimensions")
    rust_matrix = re.search(r"^        rust: \[([^]]+)]$", workflow, re.MULTILINE)
    if rust_matrix is None:
        fail("CI compiler matrix is missing")
    workflow_compilers = tuple(item.strip() for item in rust_matrix.group(1).split(","))
    if workflow_compilers != COMPILERS:
        fail("CI compiler matrix differs from constant-time coverage")
    for target in TARGETS:
        if workflow.count(f"          - {target}\n") != 1:
            fail(f"CI target coverage drifted: {target}")

    checks = (root / "scripts/checks.sh").read_text(encoding="utf-8")
    command = (
        "scripts/constant-time/check-constant-time-codegen.sh 1.97.1 "
        "x86_64-unknown-linux-gnu"
    )
    if command not in checks:
        fail("ordinary checks omit latest-host constant-time evidence")
    if "python3 scripts/constant-time/test-constant-time-codegen.py" not in checks:
        fail("ordinary checks omit constant-time assembly regression fixtures")
