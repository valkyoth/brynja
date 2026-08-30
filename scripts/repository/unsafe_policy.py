#!/usr/bin/env python3
"""Validate Brynja's exact, hash-bound unsafe implementation inventory."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


ALLOWED = {
    Path("crates/brynja-core/src/secret_memory_volatile.rs"): (
        "b056f1b562b4d1507305c8b79d1c53d63dfc842cf59992dbc9df30e65f051217",
        1,
        0,
        1,
    ),
    Path("crates/brynja-crypto-cpu/src/sha256.rs"): (
        "ab654d3dc132c6401a19497c4893fa1b000de7c298ae864c5b849843f5ffb27b", 0, 2, 0,
    ),
    Path("crates/brynja-crypto-cpu/src/x86_sha.rs"): (
        "b6cbff47cc6b0d4304fd60d5001d5b21b94aa6c2659ea809422e947a351f2e28", 2, 1, 2,
    ),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha2.rs"): (
        "b2c38b0d8fa13e3010fa3a0f85753505d8e994c00327da1bdf8651fd6f5e3353", 8, 2, 8,
    ),
    Path("crates/brynja-crypto-cpu/src/riscv64_zknh.rs"): (
        "4666c10486046cdd5a7caf8c99dc1c87b41c4f4ae4aa697a966067b89b38c619", 8, 2, 8,
    ),
    Path("crates/brynja-crypto-cpu/src/keccak.rs"): (
        "faaa0fb943f8a518b4e45797da4fc01382450626e56f6c9a81eddfebcfdd9c31", 0, 1, 0,
    ),
    Path("crates/brynja-crypto-cpu/src/x86_avx2_keccak.rs"): (
        "8f917e7ff784bb75646c526914de27e3b4eb8b15cc82b8a471edc0af1221d5b3", 3, 1, 3,
    ),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha3_keccak.rs"): (
        "7fafd5d7d568bd13c7c77ffbedc2d053cd41f1e0ce0cefb7161fb5efc455089d", 3, 1, 3,
    ),
    Path("crates/brynja-crypto-cpu-std/src/runtime_detection.rs"): (
        "f80399ec92f54a4a7deaf5588e729908a1f730549f30de5bdfdc826c6cb31de5", 1, 0, 1,
    ),
}
UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
UNSAFE_ITEM = re.compile(r"\bunsafe\s+(?:fn|impl|trait)\b")
UNSAFE_ALLOW = "allow(unsafe_code)"
FORBIDDEN_IDENTIFIER = re.compile(
    r"\b(?:unsafe|unsafe_code|asm|global_asm|llvm_asm|naked_asm|include|path)\b"
)
FOREIGN_ABI = re.compile(r'\bextern\s*(?:/\*.*?\*/\s*)?"', re.DOTALL)


class UnsafePolicyError(RuntimeError):
    """The unsafe inventory differs from the approved reviewed exceptions."""


def fail(message: str) -> None:
    raise UnsafePolicyError(message)


def validate(root: Path) -> None:
    cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
    if cargo.count('unsafe_code = "deny"') != 1 or 'unsafe_code = "forbid"' in cargo:
        fail("workspace unsafe lint must be deny for the isolated module exception")

    sources = sorted((root / "crates").glob("**/*.rs"))
    if not sources:
        fail("unsafe policy found no Rust source inventory")
    allowed_paths = {root / relative for relative in ALLOWED}
    if not allowed_paths.issubset(sources):
        fail("an approved unsafe module is missing")

    for path in sources:
        crates_root = root / "crates"
        relative_source = path.relative_to(crates_root)
        current = crates_root
        parent_is_symlink = False
        for component in relative_source.parts[:-1]:
            current /= component
            parent_is_symlink = parent_is_symlink or current.is_symlink()
        if not path.is_file() or path.is_symlink() or parent_is_symlink:
            fail(f"Rust source must be a regular non-symlink file: {path}")
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(root)
        if path in allowed_paths:
            relative = path.relative_to(root)
            expected_hash, blocks, items, proofs = ALLOWED[relative]
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != expected_hash:
                fail("approved unsafe module changed; reopen security review")
            validate_allowed(relative, text, blocks, items, proofs)
        elif FORBIDDEN_IDENTIFIER.search(text) is not None or FOREIGN_ABI.search(text) is not None:
            fail(f"unapproved low-level or code-inclusion token: {relative}")

    library = (root / "crates/brynja-core/src/lib.rs").read_text(encoding="utf-8")
    if library.count("mod secret_memory_volatile;") != 1:
        fail("volatile-store module must remain private and declared exactly once")
    if "pub mod secret_memory_volatile" in library:
        fail("volatile-store implementation module became public")


def validate_allowed(
    relative: Path,
    text: str,
    expected_blocks: int,
    expected_items: int,
    expected_proofs: int,
) -> None:
    if text.count(UNSAFE_ALLOW) != 1:
        fail("approved module must contain one exact unsafe-code allowance")
    if len(UNSAFE_BLOCK.findall(text)) != expected_blocks:
        fail(f"approved unsafe-block inventory changed: {relative}")
    if len(UNSAFE_ITEM.findall(text)) != expected_items:
        fail(f"approved unsafe-item inventory changed: {relative}")
    if text.count("// SAFETY:") != expected_proofs:
        fail(f"approved local safety-proof inventory changed: {relative}")
    if relative == Path("crates/brynja-core/src/secret_memory_volatile.rs"):
        if text.count("core::ptr::write_volatile") != 1:
            fail("approved module must use exactly one volatile-store call site")
        if "core::ptr::from_mut(byte)" not in text:
            fail("volatile pointer must derive from each live exclusive byte reference")
        if "compiler_fence(Ordering::SeqCst)" not in text:
            fail("volatile loop must retain its final compiler barrier")
    elif relative.name in {
        "x86_sha.rs", "aarch64_sha2.rs", "riscv64_zknh.rs",
        "x86_avx2_keccak.rs", "aarch64_sha3_keccak.rs",
    }:
        if "#[target_feature" not in text or "core::arch" not in text:
            fail(f"CPU kernel lost its intrinsic boundary: {relative}")
        if relative.name == "riscv64_zknh.rs":
            if text.count("asm!(") != 6 or "global_asm!(" in text:
                fail("RISC-V kernel inline-assembly inventory drifted")
        elif re.search(r'extern\s+"C"|\basm\s*!|\bglobal_asm\s*!', text):
            fail(f"CPU kernel introduced native linkage or assembly: {relative}")
    elif relative.name == "runtime_detection.rs":
        if "is_x86_feature_detected!" not in text or "from_runtime_detection" not in text:
            fail("runtime detector lost its reviewed attestation boundary")
