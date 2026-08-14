#!/usr/bin/env python3
"""Broken-fixture tests for the v0.22.0 SHA-256 source policy."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import sha256_policy as policy


ROOT = Path(__file__).resolve().parents[1]


def replace(root: Path, relative: Path, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture token missing: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def reject(label: str, mutation) -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-sha256-") as temporary:
        root = Path(temporary)
        copied = (
            *policy.SOURCES,
            policy.TEST,
            policy.ACCEL_TEST,
            policy.CORE_MANIFEST,
            policy.MANIFEST,
            policy.CRYPTO_MANIFEST,
            policy.PACKAGE_POLICY,
        )
        for relative in copied:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        mutation(root)
        try:
            policy.validate(root)
        except policy.Sha256PolicyError:
            return
        raise AssertionError(f"SHA-256 fixture accepted: {label}")


def main() -> int:
    reject("unsafe", lambda root: replace(root, policy.SHA256, "pub struct Sha256", "pub unsafe struct Sha256"))
    reject("ffi", lambda root: replace(root, policy.ERROR, "pub enum", 'extern "C" {}\npub enum'))
    reject("std", lambda root: replace(root, policy.ERROR, "pub enum", "use std::vec::Vec;\npub enum"))
    reject("alloc", lambda root: replace(root, policy.ERROR, "pub enum", "use alloc::vec::Vec;\npub enum"))
    reject("dynamic storage", lambda root: replace(root, policy.ERROR, "pub enum", "type Dynamic = Vec<u8>;\npub enum"))
    reject("global state", lambda root: replace(root, policy.ERROR, "pub enum", "static mut STATE: u8 = 0;\npub enum"))
    reject("intrinsic", lambda root: replace(root, policy.ERROR, "pub enum", "use core::arch;\npub enum"))
    reject("algorithm alias", lambda root: replace(root, policy.ERROR, "pub enum", "struct Sha512;\npub enum"))
    reject("length overflow", lambda root: replace(root, policy.SHA256, ".checked_add(additional)", ".checked_add(additional.saturating_add(1))"))
    reject("length ceiling", lambda root: replace(root, policy.SHA256, "*length <= Sha256::MAX_MESSAGE_BYTES", "*length < Sha256::MAX_MESSAGE_BYTES"))
    reject("padding boundary", lambda root: replace(root, policy.SHA256, "buffer_len < FINAL_BLOCK_PREFIX_BYTES", "buffer_len <= FINAL_BLOCK_PREFIX_BYTES"))
    reject("round count", lambda root: replace(root, policy.COMPRESS, "0xc671_78f2,", ""))
    reject("round arithmetic", lambda root: replace(root, policy.COMPRESS, ".wrapping_add(second)", ".saturating_add(second)"))
    reject("digest width", lambda root: replace(root, policy.DIGEST, "pub const LENGTH: usize = 32;", "pub const LENGTH: usize = 31;"))
    reject("claim", lambda root: replace(root, policy.LIB, "SHA256_IMPLEMENTED: bool = true", "SHA256_IMPLEMENTED: bool = false"))
    reject("core dependency", lambda root: replace(root, policy.CORE_MANIFEST, "[lints]", "[dependencies]\nbrynja-core = { workspace = true }\n\n[lints]"))
    reject("SHA dependency", lambda root: replace(root, policy.MANIFEST, "brynja-hash-core = { workspace = true }", "brynja-hash-core = { workspace = true }\nbrynja-core = { workspace = true }"))
    reject("crypto ownership", lambda root: replace(root, policy.CRYPTO_MANIFEST, "brynja-hash-sha2 = { workspace = true }", "brynja-core = { workspace = true }"))
    reject("package class", lambda root: replace(root, policy.PACKAGE_POLICY, '[packages.brynja-hash-sha2]\nclass = "modern-shared"', '[packages.brynja-hash-sha2]\nclass = "modern-engine"'))
    reject("consumer test", lambda root: replace(root, policy.TEST, "fn downstream_style_real_content_uses_only_public_api", "fn removed_consumer"))
    reject("oversized", lambda root: (root / policy.SHA256).write_text((root / policy.SHA256).read_text(encoding="utf-8") + "\n" * 501, encoding="utf-8"))
    reject("reviewed hash", lambda root: replace(root, policy.DIGEST, "One complete", "Complete"))
    print("SHA-256 policy rejects twenty-two unsafe, native, allocation, arithmetic, padding, package, test, size, and hash regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
