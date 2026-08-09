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
RISCV_CONDITIONAL_MNEMONICS = (
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",
    "beqz",
    "bnez",
    "bltz",
    "bgez",
    "blez",
    "bgtz",
    "bgt",
    "ble",
    "bgtu",
    "bleu",
    "c.beqz",
    "c.bnez",
)
RISCV_CONDITIONAL_BRANCH = re.compile(
    rf"^\s*(?:{'|'.join(re.escape(value) for value in RISCV_CONDITIONAL_MNEMONICS)})\b[^\n]*",
    re.MULTILINE | re.IGNORECASE,
)
X86_CONDITIONAL_BRANCH = re.compile(
    r"^\s*(?:j(?:a|ae|b|be|c|cxz|e|ecxz|g|ge|l|le|na|nae|nb|nbe|nc|ne|ng|nge|nl|nle|no|np|ns|nz|o|p|pe|po|rcxz|s|z)|loop(?:e|ne|z|nz)?)\b[^\n]*",
    re.MULTILINE,
)
AARCH64_CONDITIONAL_BRANCH = re.compile(
    r"^\s*(?:b\.[a-z]+|cbz|cbnz|tbz|tbnz)\b[^\n]*",
    re.MULTILINE,
)
THUMB_CONDITIONAL_BRANCH = re.compile(
    r"^\s*(?:b(?:eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(?:\.w)?|cbz|cbnz)\b[^\n]*",
    re.MULTILINE,
)
RISCV_SECRET_CHOICE_REGISTER = {
    "select_u8": "a2",
    "select_u16": "a2",
    "select_u32": "a2",
    "select_u64": "a4",
    "select_u128": "a3",
    "select_usize": "a2",
    "swap_u8": "a2",
    "swap_u16": "a2",
    "swap_u32": "a2",
    "swap_u64": "a2",
    "swap_u128": "a2",
    "swap_usize": "a2",
    "select_bytes": "a3",
    "swap_bytes": "a2",
}
RISCV_ARGUMENT_REGISTER_ALIASES = {
    f"x{10 + index}": f"a{index}" for index in range(8)
}
RISCV_NUMERIC_ARGUMENT_REGISTER = re.compile(r"\bx1[0-7]\b", re.IGNORECASE)


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

    barrier_markers = list(
        re.finditer(
            r"^; brynja_core::constant_time::barrier::compiler_barrier(?:::<(u8|u16|u32|u64|u128|usize)>)?$",
            llvm,
            re.MULTILINE,
        )
    )
    if len(barrier_markers) != 6:
        fail("LLVM evidence lacks six concrete compiler barriers")
    named_types = {marker.group(1) for marker in barrier_markers if marker.group(1)}
    if named_types and named_types != {"u8", "u16", "u32", "u64", "u128", "usize"}:
        fail("LLVM compiler-barrier width coverage drifted")
    for marker in barrier_markers:
        barrier_remainder = llvm[marker.end() :]
        barrier_start = barrier_remainder.find("{")
        barrier_end = barrier_remainder.find("\n}", barrier_start)
        if barrier_start < 0 or barrier_end < 0:
            fail("LLVM evidence has a malformed compiler barrier")
        barrier = barrier_remainder[barrier_start + 1 : barrier_end]
        if barrier.count('fence syncscope("singlethread") seq_cst') != 2:
            fail("LLVM evidence lost a compiler fence")
        if "asm sideeffect" not in barrier:
            fail("LLVM evidence lost the optimization barrier")


def assembly_body(assembly: str, function: str) -> str:
    labels = list(
        re.finditer(
            rf"^[^\s.:][^:]*constant_time_codegen_fixture[^:]*{function}[^:]*:$",
            assembly,
            re.MULTILINE,
        )
    )
    if len(labels) != 1:
        fail(f"assembly evidence must contain one {function} root")
    remainder = assembly[labels[0].end() :]
    boundary = re.search(
        r"^\s*(?:\.?Lfunc_end\d+:|\.globl\s+|\.def\s+)",
        remainder,
        re.MULTILINE,
    )
    if boundary is None:
        return remainder
    return remainder[: boundary.start()]


def conditional_branch_pattern(target: str) -> re.Pattern[str]:
    if target.startswith("riscv"):
        return RISCV_CONDITIONAL_BRANCH
    if target.startswith("x86_64"):
        return X86_CONDITIONAL_BRANCH
    if target.startswith("aarch64"):
        return AARCH64_CONDITIONAL_BRANCH
    if target.startswith("thumb"):
        return THUMB_CONDITIONAL_BRANCH
    fail(f"constant-time assembly target is unclassified: {target}")


def branch_target(line: str) -> str:
    target = line.split("#", 1)[0].split("//", 1)[0].strip().split()[-1]
    return target.rstrip(",")


def canonicalize_riscv_registers(body: str) -> str:
    return RISCV_NUMERIC_ARGUMENT_REGISTER.sub(
        lambda match: RISCV_ARGUMENT_REGISTER_ALIASES[match.group(0).lower()],
        body,
    )


def validate_assembly_body(function: str, body: str, target: str) -> None:
    if target.startswith("riscv"):
        body = canonicalize_riscv_registers(body)

    branches = list(conditional_branch_pattern(target).finditer(body))
    if function not in FIXED_ARRAY_FUNCTIONS and branches:
        fail(f"{function} contains a conditional {target} branch")
    for branch in branches:
        line = branch.group(0)
        if target.startswith("riscv"):
            secret_register = RISCV_SECRET_CHOICE_REGISTER.get(function)
            if secret_register is not None and re.search(
                rf"\b{re.escape(secret_register)}\b", line, re.IGNORECASE
            ):
                fail(f"{function} branches directly on the secret Choice register")

        target_label = branch_target(line)
        prior = body[: branch.start()]
        if re.search(rf"^\s*{re.escape(target_label)}:\s*$", prior, re.MULTILINE) is None:
            fail(f"{function} contains a non-public forward assembly branch")

    if target.startswith("riscv") and function in RISCV_SECRET_CHOICE_REGISTER:
        register = RISCV_SECRET_CHOICE_REGISTER[function]
        secret_address = re.compile(
            rf"^\s*(?:c\.)?(?:l(?:b|bu|h|hu|w|d)|s(?:b|h|w|d))\s+[^\n]*\([^)]*\b{register}\b[^)]*\)",
            re.MULTILINE | re.IGNORECASE,
        )
        if secret_address.search(body) is not None:
            fail(f"{function} uses the secret Choice register as a memory address")


def validate_assembly(assembly: str, target: str) -> None:
    for function in FUNCTIONS:
        validate_assembly_body(function, assembly_body(assembly, function), target)
    if FORBIDDEN_CALL.search(assembly) is not None:
        fail("assembly evidence contains a variable-work or panic symbol")


def validate(llvm_path: Path, assembly_path: Path, target: str) -> None:
    validate_llvm(llvm_path.read_text(encoding="utf-8"))
    validate_assembly(assembly_path.read_text(encoding="utf-8"), target)


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage: constant_time_codegen.py LLVM ASSEMBLY TARGET")
    validate(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
