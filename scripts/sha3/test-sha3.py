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
            policy.MIRI_SCRIPT,
            policy.SANITIZER_SCRIPT,
            policy.DIFFERENTIAL,
            policy.DIFFERENTIAL_FIXTURE,
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
    reject("maximum rate", lambda root: replace(root, policy.SPONGE, "MAX_RATE_BYTES: usize = 168", "MAX_RATE_BYTES: usize = 144"))
    reject("SHAKE suffix", lambda root: replace(root, policy.SPONGE, "SHAKE_SUFFIX: u8 = 0x1f", "SHAKE_SUFFIX: u8 = 0x06"))
    reject("final bit", lambda root: replace(root, policy.SPONGE, "*last ^= 0x80", "*last ^= 0x40"))
    reject("length overflow", lambda root: replace(root, policy.SPONGE, "current.checked_add(additional)", "current.saturating_add(additional).checked_add(0)"))
    reject("output counter", lambda root: replace(root, policy.SPONGE, "checked_output_length(self.output_bytes, additional)", "checked_message_length(self.output_bytes, additional)"))
    reject("SHA3-224 rate", lambda root: replace(root, policy.SHA3_224, "RATE_BYTES: usize = 144", "RATE_BYTES: usize = 136"))
    reject("SHA3-256 rate", lambda root: replace(root, policy.SHA3_256, "RATE_BYTES: usize = 136", "RATE_BYTES: usize = 144"))
    reject("SHA3-384 rate", lambda root: replace(root, policy.SHA3_384, "RATE_BYTES: usize = 104", "RATE_BYTES: usize = 136"))
    reject("SHA3-512 rate", lambda root: replace(root, policy.SHA3_512, "RATE_BYTES: usize = 72", "RATE_BYTES: usize = 104"))
    reject("SHAKE128 rate", lambda root: replace(root, policy.SHAKE128, "RATE_BYTES: usize = 168", "RATE_BYTES: usize = 136"))
    reject("SHAKE256 rate", lambda root: replace(root, policy.SHAKE256, "RATE_BYTES: usize = 136", "RATE_BYTES: usize = 168"))
    reject("SHA3-224 claim", lambda root: replace(root, policy.LIB, "SHA3_224_IMPLEMENTED: bool = true", "SHA3_224_IMPLEMENTED: bool = false"))
    reject("SHA3-256 claim", lambda root: replace(root, policy.LIB, "SHA3_256_IMPLEMENTED: bool = true", "SHA3_256_IMPLEMENTED: bool = false"))
    reject("SHA3-384 claim", lambda root: replace(root, policy.LIB, "SHA3_384_IMPLEMENTED: bool = true", "SHA3_384_IMPLEMENTED: bool = false"))
    reject("SHA3-512 claim", lambda root: replace(root, policy.LIB, "SHA3_512_IMPLEMENTED: bool = true", "SHA3_512_IMPLEMENTED: bool = false"))
    reject("SHAKE128 claim", lambda root: replace(root, policy.LIB, "SHAKE128_IMPLEMENTED: bool = true", "SHAKE128_IMPLEMENTED: bool = false"))
    reject("SHAKE256 claim", lambda root: replace(root, policy.LIB, "SHAKE256_IMPLEMENTED: bool = true", "SHAKE256_IMPLEMENTED: bool = false"))
    reject("SHA3-384 digest width", lambda root: replace(root, policy.DIGEST, 'Sha3_384Digest, 48, "SHA3-384"', 'Sha3_384Digest, 47, "SHA3-384"'))
    reject("SHA3-512 digest width", lambda root: replace(root, policy.DIGEST, 'Sha3_512Digest, 64, "SHA3-512"', 'Sha3_512Digest, 63, "SHA3-512"'))
    reject("adjacent algorithm", lambda root: replace(root, policy.LIB, "mod sponge;", "mod sponge;\npub struct Cshake128;"))
    reject("vector", lambda root: replace(root, policy.SHA3_256_TEST, "official_fips202_zero_and_1600_bit_vectors_match", "removed_vector"))
    reject("SHA3-384 vector", lambda root: replace(root, policy.SHA3_384_TEST, "official_fips202_zero_and_1600_bit_vectors_match", "removed_vector"))
    reject("SHA3-512 vector", lambda root: replace(root, policy.SHA3_512_TEST, "official_fips202_zero_and_1600_bit_vectors_match", "removed_vector"))
    reject("SHAKE128 vector", lambda root: replace(root, policy.SHAKE128_TEST, "official_fips202_zero_and_1600_bit_vectors_match", "removed_vector"))
    reject("SHAKE256 vector", lambda root: replace(root, policy.SHAKE256_TEST, "official_fips202_zero_and_1600_bit_vectors_match", "removed_vector"))
    reject("SHAKE long input", lambda root: replace(root, policy.SHAKE128_TEST, "standard_text_and_million_byte_outputs_match", "removed_long_input"))
    reject("SHAKE partitions", lambda root: replace(root, policy.SHAKE128_TEST, "every_output_partition_matches_one_shot_across_permutations", "removed_partitions"))
    reject("SHAKE state transition", lambda root: replace(root, policy.SHAKE256_TEST, "zero_length_and_checked_state_transitions_are_exact", "removed_transitions"))
    reject("SHAKE strength identity", lambda root: replace(root, policy.SHAKE256_TEST, "shake_strength_identities_are_distinct", "removed_identity"))
    reject("SHA-3 Miri package", lambda root: replace(root, policy.MIRI_SCRIPT, "-p brynja-hash-sha3", "-p brynja-hash-sha2"))
    reject("SHA-3 Miri test inventory", lambda root: replace(root, policy.MIRI_SCRIPT, "sha3_384 sha3_512", "sha3_384"))
    reject("SHAKE Miri test inventory", lambda root: replace(root, policy.MIRI_SCRIPT, "shake128 shake256", "shake128"))
    reject("SHA-3 sanitizer package", lambda root: replace(root, policy.SANITIZER_SCRIPT, "-p brynja-hash-sha3", "-p brynja-hash-sha2"))
    reject("SHA-3 sanitizer test targets", lambda root: replace(root, policy.SANITIZER_SCRIPT, "--tests", "--lib"))
    reject("XOF campaign maximum", lambda root: replace(root, policy.DIFFERENTIAL_FIXTURE, "MAX_XOF_OUTPUT_BYTES: usize = 343", "MAX_XOF_OUTPUT_BYTES: usize = usize::MAX"))
    reject("XOF campaign comparison", lambda root: replace(root, policy.DIFFERENTIAL_FIXTURE, "length > MAX_XOF_OUTPUT_BYTES", "length == MAX_XOF_OUTPUT_BYTES"))
    reject("XOF fallible allocation", lambda root: replace(root, policy.DIFFERENTIAL_FIXTURE, ".try_reserve_exact(length)", ".reserve_exact(length)"))
    reject("package class", lambda root: replace(root, policy.PACKAGE_POLICY, '[packages.brynja-hash-sha3]\nclass = "modern-shared"', '[packages.brynja-hash-sha3]\nclass = "modern-engine"'))
    reject("oversized", lambda root: (root / policy.KECCAK).write_text((root / policy.KECCAK).read_text(encoding="utf-8") + "\n" * 501, encoding="utf-8"))
    reject("reviewed hash", lambda root: replace(root, policy.DIGEST, "One complete", "Complete"))
    print("portable SHA-3 policy rejects forty-six boundary, permutation, padding, XOF, allocation, identity, dynamic-analysis, size, and hash regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
