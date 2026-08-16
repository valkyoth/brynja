#!/usr/bin/env python3
"""Broken-fixture tests for the portable SHA-2 source policy."""

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
            policy.SHA224_TEST,
            policy.SHA384_TEST,
            policy.SHA512_TEST,
            policy.SHA512_224_TEST,
            policy.SHA512_256_TEST,
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
    reject("length overflow", lambda root: replace(root, policy.SHA256, ".checked_add(additional)", ".checked_add(additional.saturating_add(1))"))
    reject("length ceiling", lambda root: replace(root, policy.SHA256, "*length <= Sha256::MAX_MESSAGE_BYTES", "*length < Sha256::MAX_MESSAGE_BYTES"))
    reject("public length preflight", lambda root: replace(root, policy.SHA256, "pub fn check_additional_bytes", "fn check_additional_bytes"))
    reject("padding boundary", lambda root: replace(root, policy.SHA256, "buffer_len < FINAL_BLOCK_PREFIX_BYTES", "buffer_len <= FINAL_BLOCK_PREFIX_BYTES"))
    reject("round count", lambda root: replace(root, policy.COMPRESS, "0xc671_78f2,", ""))
    reject("round arithmetic", lambda root: replace(root, policy.COMPRESS, ".wrapping_add(second)", ".saturating_add(second)"))
    reject("SHA-256 IV", lambda root: replace(root, policy.SHA256, "0x6a09_e667", "0x6a09_e668"))
    reject("SHA-256 digest width", lambda root: replace(root, policy.DIGEST, 'digest_type!(Sha256Digest, 32, "SHA-256", "256");', 'digest_type!(Sha256Digest, 31, "SHA-256", "256");'))
    reject("SHA-224 IV", lambda root: replace(root, policy.SHA224, "0xc105_9ed8", "0x6a09_e667"))
    reject("SHA-224 length ceiling", lambda root: replace(root, policy.SHA224, "*length <= Sha224::MAX_MESSAGE_BYTES", "*length < Sha224::MAX_MESSAGE_BYTES"))
    reject("SHA-224 padding boundary", lambda root: replace(root, policy.SHA224, "buffer_len < FINAL_BLOCK_PREFIX_BYTES", "buffer_len <= FINAL_BLOCK_PREFIX_BYTES"))
    reject("SHA-224 digest width", lambda root: replace(root, policy.DIGEST, 'digest_type!(Sha224Digest, 28, "SHA-224", "224");', 'digest_type!(Sha224Digest, 27, "SHA-224", "224");'))
    reject("SHA-224 claim", lambda root: replace(root, policy.LIB, "SHA224_IMPLEMENTED: bool = true", "SHA224_IMPLEMENTED: bool = false"))
    reject("SHA-224 CAVP test", lambda root: replace(root, policy.SHA224_TEST, "fn official_nist_cavp_monte_carlo_count_zero_matches", "fn removed_monte_carlo"))
    reject("SHA-224 identity test", lambda root: replace(root, policy.SHA224_TEST, "fn sha224_is_not_truncated_sha256", "fn removed_identity_test"))
    reject("SHA-384 IV", lambda root: replace(root, policy.SHA384, "0xcbbb_9d5d_c105_9ed8", "0x6a09_e667_f3bc_c908"))
    reject("SHA-512 IV", lambda root: replace(root, policy.SHA512, "0x6a09_e667_f3bc_c908", "0xcbbb_9d5d_c105_9ed8"))
    reject("SHA-512 round count", lambda root: replace(root, policy.COMPRESS64, "0x6c44_198c_4a47_5817,", ""))
    reject("SHA-512 round arithmetic", lambda root: replace(root, policy.COMPRESS64, ".wrapping_add(second)", ".saturating_add(second)"))
    reject("SHA-512 length ceiling", lambda root: replace(root, policy.SHA512_STATE, "*length <= MAX_MESSAGE_BYTES", "*length < MAX_MESSAGE_BYTES"))
    reject("SHA-512 padding boundary", lambda root: replace(root, policy.SHA512_STATE, "buffer_len < FINAL_BLOCK_PREFIX_BYTES", "buffer_len <= FINAL_BLOCK_PREFIX_BYTES"))
    reject("SHA-384 digest width", lambda root: replace(root, policy.DIGEST, 'digest_type!(Sha384Digest, 48, "SHA-384", "384");', 'digest_type!(Sha384Digest, 47, "SHA-384", "384");'))
    reject("SHA-512 digest width", lambda root: replace(root, policy.DIGEST, 'digest_type!(Sha512Digest, 64, "SHA-512", "512");', 'digest_type!(Sha512Digest, 63, "SHA-512", "512");'))
    reject("SHA-384 claim", lambda root: replace(root, policy.LIB, "SHA384_IMPLEMENTED: bool = true", "SHA384_IMPLEMENTED: bool = false"))
    reject("SHA-512 claim", lambda root: replace(root, policy.LIB, "SHA512_IMPLEMENTED: bool = true", "SHA512_IMPLEMENTED: bool = false"))
    reject("SHA-384 CAVP test", lambda root: replace(root, policy.SHA384_TEST, "fn official_nist_cavp_monte_carlo_count_zero_matches", "fn removed_monte_carlo"))
    reject("SHA-512 CAVP test", lambda root: replace(root, policy.SHA512_TEST, "fn official_nist_cavp_monte_carlo_count_zero_matches", "fn removed_monte_carlo"))
    reject("SHA-384 identity test", lambda root: replace(root, policy.SHA384_TEST, "fn sha384_is_not_truncated_sha512", "fn removed_identity_test"))
    reject("SHA-512/224 IV", lambda root: replace(root, policy.SHA512_T, "0x8c3d_37c8_1954_4da2", "0x8c3d_37c8_1954_4da3"))
    reject("SHA-512/256 IV", lambda root: replace(root, policy.SHA512_T, "0x2231_2194_fc2b_f72c", "0x2231_2194_fc2b_f72d"))
    reject("SHA-512/t mask", lambda root: replace(root, policy.SHA512_T, "0xa5a5_a5a5_a5a5_a5a5", "0xa5a5_a5a5_a5a5_a5a4"))
    reject("SHA-512/224 digest width", lambda root: replace(root, policy.DIGEST, 'digest_type!(Sha512_224Digest, 28, "SHA-512/224", "224");', 'digest_type!(Sha512_224Digest, 27, "SHA-512/224", "224");'))
    reject("SHA-512/256 digest width", lambda root: replace(root, policy.DIGEST, 'digest_type!(Sha512_256Digest, 32, "SHA-512/256", "256");', 'digest_type!(Sha512_256Digest, 31, "SHA-512/256", "256");'))
    reject("SHA-512/224 claim", lambda root: replace(root, policy.LIB, "SHA512_224_IMPLEMENTED: bool = true", "SHA512_224_IMPLEMENTED: bool = false"))
    reject("SHA-512/256 claim", lambda root: replace(root, policy.LIB, "SHA512_256_IMPLEMENTED: bool = true", "SHA512_256_IMPLEMENTED: bool = false"))
    reject("SHA-512/224 CAVP test", lambda root: replace(root, policy.SHA512_224_TEST, "fn official_nist_cavp_monte_carlo_count_zero_matches", "fn removed_monte_carlo"))
    reject("SHA-512/224 identity test", lambda root: replace(root, policy.SHA512_224_TEST, "fn trait_api_length_domain_and_algorithm_identity_are_exact", "fn removed_identity_test"))
    reject("SHA-512/256 identity test", lambda root: replace(root, policy.SHA512_256_TEST, "fn trait_api_length_domain_and_algorithm_identity_are_exact", "fn removed_identity_test"))
    reject("claim", lambda root: replace(root, policy.LIB, "SHA256_IMPLEMENTED: bool = true", "SHA256_IMPLEMENTED: bool = false"))
    reject("core dependency", lambda root: replace(root, policy.CORE_MANIFEST, "[lints]", "[dependencies]\nbrynja-core = { workspace = true }\n\n[lints]"))
    reject("SHA dependency", lambda root: replace(root, policy.MANIFEST, "brynja-hash-core = { workspace = true }", "brynja-hash-core = { workspace = true }\nbrynja-core = { workspace = true }"))
    reject("crypto ownership", lambda root: replace(root, policy.CRYPTO_MANIFEST, "brynja-hash-sha2 = { workspace = true }", "brynja-core = { workspace = true }"))
    reject("package class", lambda root: replace(root, policy.PACKAGE_POLICY, '[packages.brynja-hash-sha2]\nclass = "modern-shared"', '[packages.brynja-hash-sha2]\nclass = "modern-engine"'))
    reject("consumer test", lambda root: replace(root, policy.TEST, "fn downstream_style_real_content_uses_only_public_api", "fn removed_consumer"))
    reject("oversized", lambda root: (root / policy.SHA256).write_text((root / policy.SHA256).read_text(encoding="utf-8") + "\n" * 501, encoding="utf-8"))
    reject("reviewed hash", lambda root: replace(root, policy.DIGEST, "One complete", "Complete"))
    print("portable SHA-2 policy rejects fifty-four unsafe, native, allocation, identity, arithmetic, padding, package, test, size, and hash regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
