#!/usr/bin/env python3
"""Validate the reviewed portable FIPS 202 fixed-output SHA-3 boundary."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path

import sha3_reviewed_hashes


CRATE = Path("crates/brynja-hash-sha3")
CORE_MANIFEST = Path("crates/brynja-hash-core/Cargo.toml")
MANIFEST = CRATE / "Cargo.toml"
CRYPTO_MANIFEST = Path("crates/brynja-crypto/Cargo.toml")
PACKAGE_POLICY = Path("package-policy.toml")
LIB = CRATE / "src/lib.rs"
KECCAK = CRATE / "src/keccak.rs"
SPONGE = CRATE / "src/sponge.rs"
DIGEST = CRATE / "src/digest.rs"
ERROR = CRATE / "src/error.rs"
SHA3_224 = CRATE / "src/sha3_224.rs"
SHA3_256 = CRATE / "src/sha3_256.rs"
SHA3_384 = CRATE / "src/sha3_384.rs"
SHA3_512 = CRATE / "src/sha3_512.rs"
SHA3_224_TEST = CRATE / "tests/sha3_224.rs"
SHA3_256_TEST = CRATE / "tests/sha3_256.rs"
SHA3_384_TEST = CRATE / "tests/sha3_384.rs"
SHA3_512_TEST = CRATE / "tests/sha3_512.rs"
TEST_SUPPORT = CRATE / "tests/support/mod.rs"
DIFFERENTIAL = Path("scripts/sha3/check-sha3-differential.py")
DIFFERENTIAL_FIXTURE = Path("assurance/sha3-differential/src/main.rs")
SOURCES = (LIB, KECCAK, SPONGE, DIGEST, ERROR, SHA3_224, SHA3_256, SHA3_384, SHA3_512)
TESTS = (SHA3_224_TEST, SHA3_256_TEST, SHA3_384_TEST, SHA3_512_TEST, TEST_SUPPORT)
HASHES = {
    Path(path): digest for path, digest in sha3_reviewed_hashes.REVIEWED_HASHES.items()
}


class Sha3PolicyError(RuntimeError):
    """The reviewed portable SHA-3 boundary differs from policy."""


def fail(message: str) -> None:
    raise Sha3PolicyError(message)


def without_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def require(text: str, token: str, label: str) -> None:
    if token not in text:
        fail(f"{label} drift: {token}")


def read(root: Path, relative: Path) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        fail(f"SHA-3 boundary must be a regular file: {relative}")
    text = path.read_text(encoding="utf-8")
    if relative.suffix in {".rs", ".py"} and len(text.splitlines()) > 500:
        fail(f"SHA-3 boundary exceeds 500 lines: {relative}")
    return text


def validate(root: Path) -> None:
    expected_sources = {root / source for source in SOURCES}
    actual_sources = set((root / CRATE / "src").glob("*.rs"))
    if actual_sources != expected_sources:
        fail("SHA-3 production source inventory changed")

    loaded = {path: read(root, path) for path in (*SOURCES, *TESTS)}
    production = "\n".join(without_comments(loaded[path]) for path in SOURCES)
    for forbidden in (
        "unsafe",
        'extern "C"',
        "std::",
        "alloc::",
        "Vec<",
        "Box<",
        "static mut",
        "Atomic",
        "thread_local",
        "core::arch",
        "target_feature",
        "asm!",
        "pub fn permute",
        "pub(crate) fn permute",
    ):
        if forbidden in production:
            fail(f"SHA-3 crossed forbidden boundary: {forbidden}")

    library = without_comments(loaded[LIB])
    for token in (
        "#![no_std]",
        "mod keccak;",
        "mod sponge;",
        "pub const SHA3_224_IMPLEMENTED: bool = true;",
        "pub const SHA3_256_IMPLEMENTED: bool = true;",
        "pub const SHA3_384_IMPLEMENTED: bool = true;",
        "pub const SHA3_512_IMPLEMENTED: bool = true;",
        "pub fn sha3_224(input: &[u8]) -> Result<Sha3_224Digest, Sha3_224Error>",
        "pub fn sha3_256(input: &[u8]) -> Result<Sha3_256Digest, Sha3_256Error>",
        "pub fn sha3_384(input: &[u8]) -> Result<Sha3_384Digest, Sha3_384Error>",
        "pub fn sha3_512(input: &[u8]) -> Result<Sha3_512Digest, Sha3_512Error>",
        "#[kani::proof]",
    ):
        require(library, token, "SHA-3 package")
    for adjacent in ("Shake128", "Shake256"):
        if adjacent in library:
            fail(f"adjacent v0.24 algorithm admitted early: {adjacent}")

    keccak = without_comments(loaded[KECCAK])
    for token in (
        "const ROUND_CONSTANTS: [u64; 24]",
        "const ROTATION_OFFSETS: [u32; 25]",
        "const PI_DESTINATIONS: [usize; 25]",
        "pub(super) fn permute(state: &mut [u64; 25])",
        "for constant in ROUND_CONSTANTS",
        "c4 ^ c1.rotate_left(1)",
        "*a0 = b0 ^ ((!b1) & b2);",
        "*first ^= constant;",
    ):
        require(keccak, token, "Keccak-f[1600]")
    constants = re.findall(r"0x[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}", keccak)
    if len(constants) != 24:
        fail(f"Keccak round constant inventory changed: {len(constants)}")

    sponge = without_comments(loaded[SPONGE])
    for token in (
        "pub(super) const MAX_RATE_BYTES: usize = 144;",
        "pub(super) const SHA3_SUFFIX: u8 = 0x06;",
        "state: [u64; 25]",
        "message_bytes: u128",
        "checked_message_length(self.message_bytes, additional)?;",
        "current.checked_add(additional)",
        "*last ^= 0x80;",
        "permute(state);",
    ):
        require(sponge, token, "sponge")

    for path, algorithm, rate in (
        (SHA3_224, "Sha3_224", "144"),
        (SHA3_256, "Sha3_256", "136"),
        (SHA3_384, "Sha3_384", "104"),
        (SHA3_512, "Sha3_512", "72"),
    ):
        state = without_comments(loaded[path])
        for token in (
            f"const RATE_BYTES: usize = {rate};",
            f"pub struct {algorithm}(Sponge<RATE_BYTES>);",
            "pub fn check_additional_bytes",
            "pub fn update(&mut self, input: &[u8])",
            "impl Update for",
            "impl FixedOutput for",
        ):
            require(state, token, algorithm)
        for forbidden in (f"impl Clone for {algorithm}", f"impl Copy for {algorithm}"):
            if forbidden in state:
                fail(f"consuming SHA-3 state became duplicable: {forbidden}")

    digest = without_comments(loaded[DIGEST])
    error = without_comments(loaded[ERROR])
    for algorithm, width, bits in (
        ("Sha3_224", "28", "224"),
        ("Sha3_256", "32", "256"),
        ("Sha3_384", "48", "384"),
        ("Sha3_512", "64", "512"),
    ):
        require(
            digest,
            f'digest_type!({algorithm}Digest, {width}, "SHA3-{bits}", "{bits}");',
            f"{algorithm} digest",
        )
        require(
            error,
            f'error_type!({algorithm}Error, "SHA3-{bits}");',
            f"{algorithm} error",
        )

    tests = "\n".join(loaded[path] for path in TESTS)
    for token in (
        "official_fips202_zero_and_1600_bit_vectors_match",
        "standard_text_and_million_byte_vectors_match",
        "suffix_and_rate_boundaries_have_exact_digests",
        "every_streaming_partition_matches_one_shot",
        "sha3_domain_is_not_raw_keccak",
        "trait_api_and_algorithm_identity_are_exact",
    ):
        require(tests, token, "SHA-3 tests")

    manifest = tomllib.loads(read(root, MANIFEST))
    if manifest.get("dependencies") != {"brynja-hash-core": {"workspace": True}}:
        fail("SHA-3 dependency boundary changed")
    crypto = tomllib.loads(read(root, CRYPTO_MANIFEST))
    if crypto.get("dependencies", {}).get("brynja-hash-sha3") != {"workspace": True}:
        fail("cryptographic composition no longer consumes SHA-3 leaf ownership")
    policy = tomllib.loads(read(root, PACKAGE_POLICY))
    entry = policy.get("packages", {}).get("brynja-hash-sha3")
    if entry != {
        "class": "modern-shared",
        "publish": "crates-io",
        "required": ["brynja-hash-core"],
        "optional": {},
    }:
        fail("SHA-3 package classification changed")

    for path, expected in HASHES.items():
        actual = hashlib.sha256((root / path).read_bytes()).hexdigest()
        if actual != expected:
            fail(f"reviewed SHA-3 hash changed: {path}")
