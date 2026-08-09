#!/usr/bin/env python3
"""Validate optimized v0.12.0 constant-time evidence roots."""

from __future__ import annotations

import re
import sys
from pathlib import Path


FUNCTIONS = (
    "equal_u8",
    "select_u8",
    "swap_u8",
    "equal_u16",
    "select_u16",
    "swap_u16",
    "equal_u32",
    "select_u32",
    "swap_u32",
    "equal_u64",
    "select_u64",
    "swap_u64",
    "equal_u128",
    "select_u128",
    "swap_u128",
    "equal_usize",
    "select_usize",
    "swap_usize",
    "equal_bytes",
    "select_bytes",
    "swap_bytes",
    "barrier_word",
)
FORBIDDEN_CALL = re.compile(r"(?:mem(?:cmp|chr)|bcmp|panic|bounds_check)", re.IGNORECASE)
BRANCH = re.compile(r"^\s*(?:br|switch|invoke)\b", re.MULTILINE)
FIXED_ARRAY_FUNCTIONS = {"equal_bytes", "select_bytes", "swap_bytes"}


class CodegenError(RuntimeError):
    """The emitted constant-time evidence violates its narrow claim."""


def fail(message: str) -> None:
    raise CodegenError(message)


def llvm_body(llvm: str, function: str) -> str:
    marker = f"; brynja_constant_time_codegen_fixture::{function}\n"
    if llvm.count(marker) != 1:
        fail(f"LLVM evidence must contain one {function} root")
    remainder = llvm.split(marker, 1)[1]
    definition = remainder.find("define ")
    if definition < 0:
        fail(f"LLVM evidence lacks {function} definition")
    body_start = remainder.find("{", definition)
    body_end = remainder.find("\n}", body_start)
    if body_start < 0 or body_end < 0:
        fail(f"LLVM evidence has malformed {function} definition")
    return remainder[body_start + 1 : body_end]


def validate_llvm(llvm: str) -> None:
    bodies = {function: llvm_body(llvm, function) for function in FUNCTIONS}
    for function, body in bodies.items():
        if FORBIDDEN_CALL.search(body) is not None:
            fail(f"{function} emitted a variable-work or panic call")
        branches = BRANCH.findall(body)
        if function not in FIXED_ARRAY_FUNCTIONS and branches:
            fail(f"{function} emitted value-dependent LLVM control flow")
        if function in FIXED_ARRAY_FUNCTIONS and branches:
            if len(branches) != 2 or "br label" not in body or "br i1" not in body:
                fail(f"{function} emitted a non-canonical fixed loop")
            if re.search(r"icmp eq i(?:32|64) [^\n]+, 32", body) is None:
                fail(f"{function} loop is not bound to the public width 32")

    barrier_markers = re.findall(
        r"; brynja_core::constant_time::barrier::compiler_barrier(?:::<u64>)?\n",
        llvm,
    )
    if len(barrier_markers) != 1:
        fail("LLVM evidence lacks one concrete compiler barrier")
    barrier_remainder = llvm.split(barrier_markers[0], 1)[1]
    barrier_start = barrier_remainder.find("{")
    barrier_end = barrier_remainder.find("\n}", barrier_start)
    barrier = barrier_remainder[barrier_start + 1 : barrier_end]
    if barrier.count('fence syncscope("singlethread") seq_cst') != 2:
        fail("LLVM evidence lost a compiler fence")
    if "asm sideeffect" not in barrier:
        fail("LLVM evidence lost the optimization barrier")


def validate_assembly(assembly: str) -> None:
    for function in FUNCTIONS:
        labels = re.findall(
            rf"^[^\s.:][^:]*constant_time_codegen_fixture[^:]*{function}[^:]*:$",
            assembly,
            re.MULTILINE,
        )
        if len(labels) != 1:
            fail(f"assembly evidence must contain one {function} root")
    if FORBIDDEN_CALL.search(assembly) is not None:
        fail("assembly evidence contains a variable-work or panic symbol")


def validate(llvm_path: Path, assembly_path: Path) -> None:
    validate_llvm(llvm_path.read_text(encoding="utf-8"))
    validate_assembly(assembly_path.read_text(encoding="utf-8"))


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: constant_time_codegen.py LLVM ASSEMBLY")
    validate(Path(sys.argv[1]), Path(sys.argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
