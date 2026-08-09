#!/usr/bin/env python3
"""Validate Brynja's single narrowly admitted unsafe implementation site."""

from __future__ import annotations

import re
from pathlib import Path


ALLOWED = Path("crates/brynja-core/src/secret_memory_volatile.rs")
UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
UNSAFE_ITEM = re.compile(r"\bunsafe\s+(?:fn|impl|trait)\b")
UNSAFE_ALLOW = "allow(unsafe_code)"
FORBIDDEN_LOW_LEVEL = ("asm!", "global_asm!", "naked_asm!", 'extern "')


class UnsafePolicyError(RuntimeError):
    """The unsafe inventory differs from the approved v0.11.0 exception."""


def fail(message: str) -> None:
    raise UnsafePolicyError(message)


def validate(root: Path) -> None:
    cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
    if cargo.count('unsafe_code = "deny"') != 1 or 'unsafe_code = "forbid"' in cargo:
        fail("workspace unsafe lint must be deny for the isolated module exception")

    sources = sorted((root / "crates").glob("**/*.rs"))
    if not sources:
        fail("unsafe policy found no Rust source inventory")
    allowed_path = root / ALLOWED
    if allowed_path not in sources:
        fail("approved volatile-store module is missing")

    for path in sources:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(root)
        for token in FORBIDDEN_LOW_LEVEL:
            if token in text:
                fail(f"assembly or FFI remains unapproved: {relative}")
        if path == allowed_path:
            validate_allowed(text)
        elif (
            UNSAFE_ALLOW in text
            or UNSAFE_BLOCK.search(text) is not None
            or UNSAFE_ITEM.search(text) is not None
        ):
            fail(f"unsafe Rust escaped the approved module: {relative}")

    library = (root / "crates/brynja-core/src/lib.rs").read_text(encoding="utf-8")
    if library.count("mod secret_memory_volatile;") != 1:
        fail("volatile-store module must remain private and declared exactly once")
    if "pub mod secret_memory_volatile" in library:
        fail("volatile-store implementation module became public")


def validate_allowed(text: str) -> None:
    if text.count(UNSAFE_ALLOW) != 1:
        fail("approved module must contain one exact unsafe-code allowance")
    if len(UNSAFE_BLOCK.findall(text)) != 1 or UNSAFE_ITEM.search(text) is not None:
        fail("approved module must contain one unsafe block and no unsafe items")
    if text.count("core::ptr::write_volatile") != 1:
        fail("approved module must use exactly one volatile-store call site")
    if text.count("// SAFETY:") != 1:
        fail("approved unsafe block must carry one local safety proof")
    if "core::ptr::from_mut(byte)" not in text:
        fail("volatile pointer must derive from each live exclusive byte reference")
    if "compiler_fence(Ordering::SeqCst)" not in text:
        fail("volatile loop must retain its final compiler barrier")
