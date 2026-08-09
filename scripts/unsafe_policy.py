#!/usr/bin/env python3
"""Validate Brynja's single narrowly admitted unsafe implementation site."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


ALLOWED = Path("crates/brynja-core/src/secret_memory_volatile.rs")
EXPECTED_ALLOWED_SHA256 = (
    "2746e34bfd55c80def2acf6afdfd6798d"
    "51291ea4255732e26a360d17d43dfb1"
)
UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
UNSAFE_ITEM = re.compile(r"\bunsafe\s+(?:fn|impl|trait)\b")
UNSAFE_ALLOW = "allow(unsafe_code)"
FORBIDDEN_IDENTIFIER = re.compile(
    r"\b(?:unsafe|unsafe_code|extern|asm|global_asm|llvm_asm|naked_asm|include|path)\b"
)


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
        if path == allowed_path:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != EXPECTED_ALLOWED_SHA256:
                fail("approved unsafe module changed; reopen security review")
            validate_allowed(text)
        elif FORBIDDEN_IDENTIFIER.search(text) is not None:
            fail(f"unapproved low-level or code-inclusion token: {relative}")

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
