#!/usr/bin/env python3
"""Validate the reviewed portable SHA-224/SHA-256 boundary."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path


CORE_LIB = Path("crates/brynja-hash-core/src/lib.rs")
LIB = Path("crates/brynja-hash-sha2/src/lib.rs")
COMPRESS = Path("crates/brynja-hash-sha2/src/compress.rs")
DIGEST = Path("crates/brynja-hash-sha2/src/digest.rs")
ERROR = Path("crates/brynja-hash-sha2/src/error.rs")
SHA256 = Path("crates/brynja-hash-sha2/src/sha256.rs")
SHA224 = Path("crates/brynja-hash-sha2/src/sha224.rs")
TEST = Path("crates/brynja-hash-sha2/tests/sha256.rs")
SHA224_TEST = Path("crates/brynja-hash-sha2/tests/sha224.rs")
ACCEL_TEST = Path("crates/brynja-hash-sha2/tests/sha256_accelerated.rs")
CORE_MANIFEST = Path("crates/brynja-hash-core/Cargo.toml")
MANIFEST = Path("crates/brynja-hash-sha2/Cargo.toml")
CRYPTO_MANIFEST = Path("crates/brynja-crypto/Cargo.toml")
PACKAGE_POLICY = Path("package-policy.toml")
SOURCES = (CORE_LIB, LIB, COMPRESS, DIGEST, ERROR, SHA224, SHA256)
EXPECTED_SHA256 = {
    CORE_LIB: "4655d8df05873a89689af1250dfeab76b82ac05d165a92c99ff65565624c7827",
    LIB: "6ae37d8f86749cfe84050e2051e5496247abf453d1eeed5bf283924ee5147a67",
    COMPRESS: "d4229f08e40392976f354eaf81f5d5cd03069d5f3c497e2cf481f65a9848e4b1",
    DIGEST: "039fb124df20825dac757ffd7a02df3c411edd1322dec39659a970ee91ce607f",
    ERROR: "f87dceddfd44024af90b164ca0d01f34a872e8b773b559adbf20ba82b4b24bb3",
    SHA224: "69cebc10d3e94cc0fd57f5b45e9de406e04e1c6f2029ce668be520dbf40d7659",
    SHA256: "efbe3a588947e127dd0b0cecbe2b3e3b0a876a354d8d1f798052060d35ddb68d",
}
EXPECTED_TEST_SHA256 = {
    SHA224_TEST: "4a154a5293aa7fca5862fe1b383807998baa69b5eb5dd1ae2393b11d2c4fecb5",
    TEST: "c3eebf6ae0202321f72ddc131691720c94709e5281f905a5bd7d0fe4a603a3d1",
    ACCEL_TEST: "576c89cbbca4f0f45ce88efe750bd2976c5fa547becaae9fdbff103a38f66ae1",
}


class Sha256PolicyError(RuntimeError):
    """The reviewed portable SHA-256 boundary differs from policy."""


def fail(message: str) -> None:
    raise Sha256PolicyError(message)


def code_without_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def require(code: str, token: str, label: str) -> None:
    if token not in code:
        fail(f"{label} drift: {token}")


def load_sources(root: Path) -> dict[Path, tuple[str, str]]:
    loaded = {}
    for relative in SOURCES:
        source = root / relative
        if not source.is_file() or source.is_symlink():
            fail(f"SHA-256 source must be a regular file: {relative}")
        text = source.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"SHA-256 source exceeds 500 lines: {relative}")
        loaded[relative] = (text, code_without_comments(text))
    return loaded


def validate_structure(sources: dict[Path, tuple[str, str]]) -> None:
    all_code = "\n".join(code for _text, code in sources.values())
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
        "Socket",
        "TcpStream",
        "UdpSocket",
        "File::",
        "Sha384",
        "Sha512",
    ):
        if forbidden in all_code:
            fail(f"SHA-256 crossed forbidden boundary: {forbidden}")

    core = sources[CORE_LIB][1]
    for token in (
        "#![no_std]",
        "pub trait Update",
        "fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;",
        "pub trait FixedOutput: Update",
        "fn finalize(self) -> Self::Output;",
    ):
        require(core, token, "hash interface")

    library = sources[LIB][1]
    for token in (
        "#![no_std]",
        "pub const SHA224_IMPLEMENTED: bool = true;",
        "pub const SHA256_IMPLEMENTED: bool = true;",
        "pub fn sha224(input: &[u8]) -> Result<Sha224Digest, Sha224Error>",
        "pub fn sha256(input: &[u8]) -> Result<Sha256Digest, Sha256Error>",
        "state.update(input)?;",
        "Ok(state.finalize())",
        "#[kani::proof]",
    ):
        require(library, token, "SHA-256 package")

    compression = sources[COMPRESS][1]
    for token in (
        "const ROUND_CONSTANTS: [u32; 64]",
        "pub(crate) fn compress(state: &mut [u32; 8], block: &[u8; 64])",
        "for (constant, word) in ROUND_CONSTANTS.iter().zip(schedule.iter())",
        ".wrapping_add(",
        "value.rotate_right(2)",
        "value.rotate_right(6)",
        "value.rotate_right(7)",
        "value.rotate_right(17)",
    ):
        require(compression, token, "compression")
    constants = re.findall(r"0x[0-9a-f]{4}_[0-9a-f]{4}", compression)
    if len(constants) != 64:
        fail(f"SHA-256 round constant inventory changed: {len(constants)}")

    state = sources[SHA256][1]
    for token in (
        "const INITIAL_STATE: [u32; 8]",
        "pub struct Sha256",
        "pub const MAX_MESSAGE_BYTES: u64 = u64::MAX / 8;",
        "pub fn check_additional_bytes(&self, additional_bytes: u64)",
        "checked_message_length(self.message_bytes, additional_bytes).map(|_| ())",
        "u64::try_from(input.len())",
        "checked_message_length(self.message_bytes, additional)",
        ".checked_add(additional)",
        "*length <= Sha256::MAX_MESSAGE_BYTES",
        "padding_block_count(self.buffer_len) == 2",
        ".skip(FINAL_BLOCK_PREFIX_BYTES)",
        "compress_block(&mut self.state, &self.buffer)?;",
        "impl Update for Sha256",
        "impl FixedOutput for Sha256",
        "pub fn update_with_backend",
        "pub fn finalize_with_backend",
        ".ensure_healthy()",
    ):
        require(state, token, "streaming state")
    for forbidden in ("impl Clone for Sha256", "impl Copy for Sha256"):
        if forbidden in state:
            fail(f"consuming SHA-256 state became duplicable: {forbidden}")

    sha224 = sources[SHA224][1]
    for token in (
        "const INITIAL_STATE: [u32; 8]",
        "0xc105_9ed8",
        "pub struct Sha224",
        "pub const MAX_MESSAGE_BYTES: u64 = u64::MAX / 8;",
        "pub fn check_additional_bytes(&self, additional_bytes: u64)",
        "u64::try_from(input.len())",
        "checked_message_length(self.message_bytes, additional)",
        ".checked_add(additional)",
        "*length <= Sha224::MAX_MESSAGE_BYTES",
        "padding_block_count(self.buffer_len) == 2",
        ".skip(FINAL_BLOCK_PREFIX_BYTES)",
        "impl Update for Sha224",
        "impl FixedOutput for Sha224",
        "fn rejected_update_preserves_every_owned_field",
    ):
        require(sha224, token, "SHA-224 streaming state")
    for forbidden in ("impl Clone for Sha224", "impl Copy for Sha224"):
        if forbidden in sha224:
            fail(f"consuming SHA-224 state became duplicable: {forbidden}")

    digest = sources[DIGEST][1]
    for token in (
        "pub struct $name([u8; Self::LENGTH]);",
        "pub const fn as_bytes(&self) -> &[u8; Self::LENGTH]",
        "pub const fn into_bytes(self) -> [u8; Self::LENGTH]",
        'digest_type!(Sha224Digest, 28, "SHA-224", "224");',
        'digest_type!(Sha256Digest, 32, "SHA-256", "256");',
    ):
        require(digest, token, "digest")

    error = sources[ERROR][1]
    require(error, "pub enum $name", "closed error")
    require(error, 'error_type!(Sha224Error, "SHA-224");', "closed error")
    require(error, 'error_type!(Sha256Error, "SHA-256");', "closed error")
    require(error, "MessageTooLong", "closed error")
    if re.search(r"^\s+[A-Z][A-Za-z0-9_]*\s*\{", error, re.MULTILINE):
        fail("SHA-256 errors gained payload fields")


def validate_tests(root: Path) -> None:
    path = root / TEST
    if not path.is_file() or path.is_symlink():
        fail("SHA-256 tests must be a regular file")
    text = path.read_text(encoding="utf-8")
    if len(text.splitlines()) > 500:
        fail("SHA-256 tests exceed 500 lines")
    for token in (
        "fn official_fips_vectors",
        "fn padding_boundaries_have_exact_digests",
        "fn every_streaming_partition_matches_one_shot",
        "fn downstream_style_real_content_uses_only_public_api",
        "fn public_length_preflight_is_exact_and_non_mutating",
        "let repeated = [b'a'; 1_000];",
        "for _ in 0..1_000",
        "for chunk_size in 1..=80",
    ):
        require(text, token, "SHA-256 tests")
    sha224_path = root / SHA224_TEST
    if not sha224_path.is_file() or sha224_path.is_symlink():
        fail("SHA-224 tests must be a regular file")
    sha224_text = sha224_path.read_text(encoding="utf-8")
    if len(sha224_text.splitlines()) > 500:
        fail("SHA-224 tests exceed 500 lines")
    for token in (
        "fn official_short_and_long_vectors_match_fips_and_nist_cavp",
        "fn official_million_a_vector_matches",
        "fn official_nist_cavp_monte_carlo_count_zero_matches",
        "fn every_padding_boundary_matches_independent_expected_results",
        "fn every_two_part_split_and_fixed_chunk_width_matches_one_shot",
        "fn trait_api_and_checked_length_are_directly_usable",
        "fn sha224_is_not_truncated_sha256",
        "for _ in 0..1_000",
        "for split in 0..=message.len()",
        "for width in 1..=message.len()",
    ):
        require(sha224_text, token, "SHA-224 tests")
    accelerated = root / ACCEL_TEST
    if not accelerated.is_file() or accelerated.is_symlink():
        fail("accelerated SHA-256 tests must be a regular file")
    accelerated_text = accelerated.read_text(encoding="utf-8")
    if len(accelerated_text.splitlines()) > 500:
        fail("accelerated SHA-256 tests exceed 500 lines")
    for token in (
        "fn statically_proven_backend_matches_scalar_when_available",
        "Sha256BackendSession::for_compiled_target()",
        "for length in [0_usize, 1, 55, 56, 63, 64, 65, 127, 128, 192, 193]",
        "for width in 1..=67",
        "state.update_with_backend(chunk, &backend)",
    ):
        require(accelerated_text, token, "accelerated SHA-256 tests")
    for relative, expected_hash in EXPECTED_TEST_SHA256.items():
        digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if digest != expected_hash:
            fail(f"SHA-2 reviewed test hash drift: {relative}")


def validate_packages(root: Path) -> None:
    core = tomllib.loads((root / CORE_MANIFEST).read_text(encoding="utf-8"))
    if core.get("dependencies"):
        fail("brynja-hash-core gained a dependency")
    manifest = tomllib.loads((root / MANIFEST).read_text(encoding="utf-8"))
    if set(manifest.get("dependencies", {})) != {"brynja-hash-core", "brynja-crypto-cpu"}:
        fail("brynja-hash-sha2 dependency boundary changed")
    crypto = tomllib.loads((root / CRYPTO_MANIFEST).read_text(encoding="utf-8"))
    if set(crypto.get("dependencies", {})) != {"brynja-hash-sha2"}:
        fail("brynja-crypto SHA-256 ownership changed")
    if core.get("features") != {"default": []}:
        fail("hash core feature boundary changed")
    if manifest.get("features") != {
        "default": [],
        "cpu": ["dep:brynja-crypto-cpu"],
    }:
        fail("SHA-2 feature boundary changed")

    policy = tomllib.loads((root / PACKAGE_POLICY).read_text(encoding="utf-8"))
    expected = {
        "brynja-hash-core": {
            "class": "modern-shared",
            "publish": "crates-io",
            "required": [],
            "optional": {},
        },
        "brynja-hash-sha2": {
            "class": "modern-shared",
            "publish": "crates-io",
            "required": ["brynja-hash-core"],
            "optional": {"cpu": "brynja-crypto-cpu"},
        },
    }
    for name, entry in expected.items():
        if policy["packages"].get(name) != entry:
            fail(f"{name} package classification changed")


def validate_hashes(sources: dict[Path, tuple[str, str]]) -> None:
    for relative, (text, _code) in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"SHA-256 reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_tests(root)
    validate_packages(root)
    validate_hashes(sources)
