#!/usr/bin/env python3
"""Broken-fixture tests for the portable SHA-3 source policy."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import sha3_policy as policy


ROOT = Path(__file__).resolve().parents[2]


def replace(root: Path, relative: Path, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture token missing: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def reject(label: str, mutation) -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-sha3-") as temporary:
        root = Path(temporary)
        copied = (
            *policy.SOURCES,
            *policy.TESTS,
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
        except policy.Sha3PolicyError:
            return
        raise AssertionError(f"SHA-3 fixture accepted: {label}")


def main() -> int:
    reject("unsafe", lambda root: replace(root, policy.KECCAK, "pub(super) fn permute", "pub(super) unsafe fn permute"))
    reject("public permutation", lambda root: replace(root, policy.KECCAK, "pub(super) fn permute", "pub fn permute"))
    reject("round count", lambda root: replace(root, policy.KECCAK, "0x8000_0000_8000_8008,", ""))
    reject("theta", lambda root: replace(root, policy.KECCAK, "c4 ^ c1.rotate_left(1)", "c4 ^ c1.rotate_left(2)"))
    reject("chi", lambda root: replace(root, policy.KECCAK, "*a0 = b0 ^ ((!b1) & b2);", "*a0 = b0 ^ (b1 & b2);"))
    reject("suffix", lambda root: replace(root, policy.SPONGE, "SHA3_SUFFIX: u8 = 0x06", "SHA3_SUFFIX: u8 = 0x01"))
    reject("final bit", lambda root: replace(root, policy.SPONGE, "*last ^= 0x80", "*last ^= 0x40"))
    reject("length overflow", lambda root: replace(root, policy.SPONGE, "current.checked_add(additional)", "current.saturating_add(additional).checked_add(0)"))
    reject("SHA3-224 rate", lambda root: replace(root, policy.SHA3_224, "RATE_BYTES: usize = 144", "RATE_BYTES: usize = 136"))
    reject("SHA3-256 rate", lambda root: replace(root, policy.SHA3_256, "RATE_BYTES: usize = 136", "RATE_BYTES: usize = 144"))
    reject("SHA3-224 claim", lambda root: replace(root, policy.LIB, "SHA3_224_IMPLEMENTED: bool = true", "SHA3_224_IMPLEMENTED: bool = false"))
    reject("SHA3-256 claim", lambda root: replace(root, policy.LIB, "SHA3_256_IMPLEMENTED: bool = true", "SHA3_256_IMPLEMENTED: bool = false"))
    reject("adjacent algorithm", lambda root: replace(root, policy.LIB, "mod sponge;", "mod sponge;\npub struct Shake128;"))
    reject("vector", lambda root: replace(root, policy.SHA3_256_TEST, "official_fips202_zero_and_1600_bit_vectors_match", "removed_vector"))
    reject("package class", lambda root: replace(root, policy.PACKAGE_POLICY, '[packages.brynja-hash-sha3]\nclass = "modern-shared"', '[packages.brynja-hash-sha3]\nclass = "modern-engine"'))
    reject("oversized", lambda root: (root / policy.KECCAK).write_text((root / policy.KECCAK).read_text(encoding="utf-8") + "\n" * 501, encoding="utf-8"))
    reject("reviewed hash", lambda root: replace(root, policy.DIGEST, "One complete", "Complete"))
    print("portable SHA-3 policy rejects seventeen boundary, permutation, padding, identity, test, size, and hash regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
