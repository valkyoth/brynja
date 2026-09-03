#!/usr/bin/env python3
"""Validate the v0.11.0 emitted-code coverage contract."""

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
    "1.98.0",
    "1.98.1",
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
EXCLUSIONS = (
    "registers",
    "caller-or-compiler-created-copies",
    "cpu-caches",
    "device-caches",
    "dma-visible-copies",
    "crash-dumps",
    "suspend-images",
    "physical-memory-remanence",
    "concurrent-access",
    "mem-forget-or-process-termination",
)


class EvidenceError(RuntimeError):
    """The zeroization evidence matrix or its execution binding drifted."""


def fail(message: str) -> None:
    raise EvidenceError(message)


def validate(root: Path) -> None:
    path = root / "assurance/zeroization-matrix.toml"
    with path.open("rb") as handle:
        matrix = tomllib.load(handle)
    if set(matrix) != {"schema", "claim", "coverage", "dynamic", "exclusions"}:
        fail("zeroization matrix sections drifted")
    if matrix["schema"] != {"version": 1, "milestone": "0.11.0"}:
        fail("zeroization matrix schema drifted")
    if matrix["claim"] != {
        "scope": "complete-exclusively-borrowed-rust-allocation",
        "method": "per-byte-volatile-zero-store-plus-compiler-barrier",
        "unsafe_module": "crates/brynja-core/src/secret_memory_volatile.rs",
        "artifacts": ["mir", "llvm-ir", "assembly"],
    }:
        fail("zeroization claim or artifact set drifted")
    coverage = matrix["coverage"]
    if (
        tuple(coverage.get("compilers", ())) != COMPILERS
        or coverage.get("compiler_target") != "x86_64-unknown-linux-gnu"
        or coverage.get("target_compiler") != "1.98.1"
        or tuple(coverage.get("targets", ())) != TARGETS
    ):
        fail("zeroization compiler or target coverage drifted")
    if tuple(matrix["exclusions"].get("values", ())) != EXCLUSIONS:
        fail("zeroization claim exclusions drifted")
    if matrix["dynamic"] != {
        "toolchain": "nightly-2026-09-03",
        "execution": "local-pre-tag",
        "miri": True,
        "address_sanitizer": True,
        "test_target": "x86_64-unknown-linux-gnu",
    }:
        fail("zeroization dynamic-analysis policy drifted")

    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    compiler_step = (
        'run: scripts/zeroization/check-zeroization-codegen.sh "${{ matrix.rust }}" '
        "x86_64-unknown-linux-gnu"
    )
    target_step = (
        'run: scripts/zeroization/check-zeroization-codegen.sh 1.98.1 "${{ matrix.target }}"'
    )
    if compiler_step not in workflow or target_step not in workflow:
        fail("CI does not execute both zeroization evidence dimensions")
    for command in (
        "scripts/zeroization/check-zeroization-miri.sh",
        "scripts/zeroization/check-zeroization-sanitizer.sh",
    ):
        if command in workflow:
            fail("ordinary CI must not execute full zeroization dynamic analysis")
    rust_matrix = re.search(r"^        rust: \[([^]]+)]$", workflow, re.MULTILINE)
    if rust_matrix is None:
        fail("CI compiler matrix is missing")
    workflow_compilers = tuple(
        item.strip() for item in rust_matrix.group(1).split(",")
    )
    if workflow_compilers != COMPILERS:
        fail("CI compiler matrix differs from zeroization coverage")
    for target in TARGETS:
        if workflow.count(f"          - {target}\n") != 1:
            fail(f"CI target coverage drifted: {target}")

    checks = (root / "scripts/checks.sh").read_text(encoding="utf-8")
    if (
        "scripts/zeroization/check-zeroization-codegen.sh 1.98.1 "
        "x86_64-unknown-linux-gnu" not in checks
    ):
        fail("ordinary repository checks omit latest-host codegen evidence")
    tag_gate = (root / "scripts/tag_gate.sh").read_text(encoding="utf-8")
    for command in (
        "scripts/zeroization/check-zeroization-miri.sh",
        "scripts/zeroization/check-zeroization-sanitizer.sh",
    ):
        if tag_gate.count(command) != 1:
            fail("local tag gate omits pinned zeroization dynamic analysis")
