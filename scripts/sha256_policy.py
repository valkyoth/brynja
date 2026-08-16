#!/usr/bin/env python3
"""Validate the reviewed complete portable FIPS 180-4 SHA-2 boundary."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path

import sha2_reviewed_hashes

CORE_LIB = Path("crates/brynja-hash-core/src/lib.rs")
LIB = Path("crates/brynja-hash-sha2/src/lib.rs")
COMPRESS = Path("crates/brynja-hash-sha2/src/compress.rs")
DIGEST = Path("crates/brynja-hash-sha2/src/digest.rs")
ERROR = Path("crates/brynja-hash-sha2/src/error.rs")
SHA256 = Path("crates/brynja-hash-sha2/src/sha256.rs")
SHA224 = Path("crates/brynja-hash-sha2/src/sha224.rs")
COMPRESS64 = Path("crates/brynja-hash-sha2/src/compress64.rs")
SHA512_STATE = Path("crates/brynja-hash-sha2/src/sha512_state.rs")
SHA384 = Path("crates/brynja-hash-sha2/src/sha384.rs")
SHA512 = Path("crates/brynja-hash-sha2/src/sha512.rs")
SHA512_T = Path("crates/brynja-hash-sha2/src/sha512_t.rs")
SHA512_224 = Path("crates/brynja-hash-sha2/src/sha512_224.rs")
SHA512_256 = Path("crates/brynja-hash-sha2/src/sha512_256.rs")
TEST = Path("crates/brynja-hash-sha2/tests/sha256.rs")
SHA224_TEST = Path("crates/brynja-hash-sha2/tests/sha224.rs")
SHA384_TEST = Path("crates/brynja-hash-sha2/tests/sha384.rs")
SHA512_TEST = Path("crates/brynja-hash-sha2/tests/sha512.rs")
SHA512_224_TEST = Path("crates/brynja-hash-sha2/tests/sha512_224.rs")
SHA512_256_TEST = Path("crates/brynja-hash-sha2/tests/sha512_256.rs")
ACCEL_TEST = Path("crates/brynja-hash-sha2/tests/sha256_accelerated.rs")
SHA2_ACCEL_TEST = Path("crates/brynja-hash-sha2/tests/sha2_accelerated.rs")
CORE_MANIFEST = Path("crates/brynja-hash-core/Cargo.toml")
MANIFEST = Path("crates/brynja-hash-sha2/Cargo.toml")
CRYPTO_MANIFEST = Path("crates/brynja-crypto/Cargo.toml")
PACKAGE_POLICY = Path("package-policy.toml")
SOURCES = (
    CORE_LIB,
    LIB,
    COMPRESS,
    COMPRESS64,
    DIGEST,
    ERROR,
    SHA224,
    SHA256,
    SHA512_STATE,
    SHA384,
    SHA512,
    SHA512_T,
    SHA512_224,
    SHA512_256,
)
EXPECTED_SHA256 = {Path(path): digest for path, digest in sha2_reviewed_hashes.SOURCE_HASHES.items()}
EXPECTED_TEST_SHA256 = {Path(path): digest for path, digest in sha2_reviewed_hashes.TEST_HASHES.items()}


class Sha256PolicyError(RuntimeError):
    """The reviewed portable SHA-2 boundary differs from policy."""


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
        "pub const SHA384_IMPLEMENTED: bool = true;",
        "pub const SHA512_IMPLEMENTED: bool = true;",
        "pub const SHA512_224_IMPLEMENTED: bool = true;",
        "pub const SHA512_256_IMPLEMENTED: bool = true;",
        "pub fn sha224(input: &[u8]) -> Result<Sha224Digest, Sha224Error>",
        "pub fn sha256(input: &[u8]) -> Result<Sha256Digest, Sha256Error>",
        "pub fn sha384(input: &[u8]) -> Result<Sha384Digest, Sha384Error>",
        "pub fn sha512(input: &[u8]) -> Result<Sha512Digest, Sha512Error>",
        "pub fn sha512_224(input: &[u8]) -> Result<Sha512_224Digest, Sha512_224Error>",
        "pub fn sha512_256(input: &[u8]) -> Result<Sha512_256Digest, Sha512_256Error>",
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

    compression64 = sources[COMPRESS64][1]
    for token in (
        "const ROUND_CONSTANTS: [u64; 80]",
        "pub(crate) fn compress(state: &mut [u64; 8], block: &[u8; 128])",
        "for (constant, word) in ROUND_CONSTANTS.iter().zip(schedule.iter())",
        ".wrapping_add(",
        "value.rotate_right(28)",
        "value.rotate_right(14)",
        "value.rotate_right(1)",
        "value.rotate_right(19)",
    ):
        require(compression64, token, "64-bit compression")
    constants64 = re.findall(r"0x[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}", compression64)
    if len(constants64) != 80:
        fail(f"SHA-512 round constant inventory changed: {len(constants64)}")

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

    shared64 = sources[SHA512_STATE][1]
    for token in (
        "const BLOCK_BYTES: usize = 128;",
        "const LENGTH_FIELD_BYTES: usize = 16;",
        "pub(crate) const MAX_MESSAGE_BYTES: u128 = u128::MAX / 8;",
        "pub(crate) struct Sha512State",
        "checked_message_length(self.message_bytes, additional_bytes).map(|_| ())",
        "let additional = input.len() as u128;",
        ".checked_add(additional)",
        "*length <= MAX_MESSAGE_BYTES",
        "padding_block_count(self.buffer_len) == 2",
        ".skip(FINAL_BLOCK_PREFIX_BYTES)",
        "message_bits.to_be_bytes()",
        "fn rejected_update_preserves_every_shared_owned_field",
    ):
        require(shared64, token, "shared SHA-512-family state")

    for relative, name, iv, words in (
        (SHA384, "Sha384", "0xcbbb_9d5d_c105_9ed8", "state.iter().take(6)"),
        (SHA512, "Sha512", "0x6a09_e667_f3bc_c908", "state.iter()"),
    ):
        algorithm = sources[relative][1]
        for token in (
            f"pub struct {name}",
            iv,
            "pub const MAX_MESSAGE_BYTES: u128 = sha512_state::MAX_MESSAGE_BYTES;",
            "pub fn check_additional_bytes(&self, additional_bytes: u128)",
            ".update(input)",
            words,
            f"impl Update for {name}",
            f"impl FixedOutput for {name}",
        ):
            require(algorithm, token, f"{name} streaming state")
        for forbidden in (f"impl Clone for {name}", f"impl Copy for {name}"):
            if forbidden in algorithm:
                fail(f"consuming {name} state became duplicable: {forbidden}")

    sha512_t = sources[SHA512_T][1]
    for token in (
        "const IV_XOR_MASK: u64 = 0xa5a5_a5a5_a5a5_a5a5;",
        "pub(crate) const SHA512_224_INITIAL_STATE: [u64; 8]",
        "0x8c3d_37c8_1954_4da2",
        "pub(crate) const SHA512_256_INITIAL_STATE: [u64; 8]",
        "0x2231_2194_fc2b_f72c",
        'derive_initial_state(b"SHA-512/224")',
        'derive_initial_state(b"SHA-512/256")',
        "*word ^= IV_XOR_MASK;",
        "compress(&mut state, &block);",
        "fn fips_sha512_t_derivation_matches_both_normative_initial_states",
        "assert_eq!(derive_sha512_224_initial_state(), SHA512_224_INITIAL_STATE);",
        "assert_eq!(derive_sha512_256_initial_state(), SHA512_256_INITIAL_STATE);",
    ):
        require(sha512_t, token, "SHA-512/t IV derivation")

    for relative, name, digest, error, initial in (
        (SHA512_224, "Sha512_224", "Sha512_224Digest", "Sha512_224Error", "SHA512_224_INITIAL_STATE"),
        (SHA512_256, "Sha512_256", "Sha512_256Digest", "Sha512_256Error", "SHA512_256_INITIAL_STATE"),
    ):
        algorithm = sources[relative][1]
        for token in (
            f"pub struct {name}",
            initial,
            "pub const MAX_MESSAGE_BYTES: u128 = sha512_state::MAX_MESSAGE_BYTES;",
            "pub fn check_additional_bytes(&self, additional_bytes: u128)",
            ".update(input)",
            "sha512_t::leftmost_bytes(self.inner.finalize())",
            f"Sha512_224Digest::from_bytes" if name == "Sha512_224" else f"Sha512_256Digest::from_bytes",
            f"impl Update for {name}",
            f"impl FixedOutput for {name}",
            f"type Output = {digest};",
            f"type Error = {error};",
        ):
            require(algorithm, token, f"{name} streaming state")
        for forbidden in (f"impl Clone for {name}", f"impl Copy for {name}"):
            if forbidden in algorithm:
                fail(f"consuming {name} state became duplicable: {forbidden}")

    digest = sources[DIGEST][1]
    for token in (
        "pub struct $name([u8; Self::LENGTH]);",
        "pub const fn as_bytes(&self) -> &[u8; Self::LENGTH]",
        "pub const fn into_bytes(self) -> [u8; Self::LENGTH]",
        'digest_type!(Sha224Digest, 28, "SHA-224", "224");',
        'digest_type!(Sha256Digest, 32, "SHA-256", "256");',
        'digest_type!(Sha384Digest, 48, "SHA-384", "384");',
        'digest_type!(Sha512Digest, 64, "SHA-512", "512");',
        'digest_type!(Sha512_224Digest, 28, "SHA-512/224", "224");',
        'digest_type!(Sha512_256Digest, 32, "SHA-512/256", "256");',
    ):
        require(digest, token, "digest")

    error = sources[ERROR][1]
    require(error, "pub enum $name", "closed error")
    require(error, 'error_type!(Sha224Error, "SHA-224", "64");', "closed error")
    require(error, 'error_type!(Sha256Error, "SHA-256", "64");', "closed error")
    require(error, 'error_type!(Sha384Error, "SHA-384", "128");', "closed error")
    require(error, 'error_type!(Sha512Error, "SHA-512", "128");', "closed error")
    require(error, 'error_type!(Sha512_224Error, "SHA-512/224", "128");', "closed error")
    require(error, 'error_type!(Sha512_256Error, "SHA-512/256", "128");', "closed error")
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
    for relative, name, distinction in (
        (SHA384_TEST, "SHA-384", "fn sha384_is_not_truncated_sha512"),
        (SHA512_TEST, "SHA-512", None),
    ):
        algorithm_path = root / relative
        if not algorithm_path.is_file() or algorithm_path.is_symlink():
            fail(f"{name} tests must be a regular file")
        algorithm_text = algorithm_path.read_text(encoding="utf-8")
        if len(algorithm_text.splitlines()) > 500:
            fail(f"{name} tests exceed 500 lines")
        for token in (
            "fn official_short_and_long_vectors_match_fips_and_nist_cavp",
            "fn official_million_a_vector_matches",
            "fn official_nist_cavp_monte_carlo_count_zero_matches",
            "fn every_padding_boundary_matches_independent_expected_results",
            "fn every_two_part_split_and_fixed_chunk_width_matches_one_shot",
            "fn trait_api_length_domain_and_real_content_are_usable",
            "for _ in 0..1_000",
            "for split in 0..=message.len()",
            "for width in 1..=message.len()",
        ):
            require(algorithm_text, token, f"{name} tests")
        if distinction is not None:
            require(algorithm_text, distinction, f"{name} tests")
    for relative, name in (
        (SHA512_224_TEST, "SHA-512/224"),
        (SHA512_256_TEST, "SHA-512/256"),
    ):
        algorithm_path = root / relative
        if not algorithm_path.is_file() or algorithm_path.is_symlink():
            fail(f"{name} tests must be a regular file")
        algorithm_text = algorithm_path.read_text(encoding="utf-8")
        if len(algorithm_text.splitlines()) > 500:
            fail(f"{name} tests exceed 500 lines")
        for token in (
            "fn official_short_and_long_nist_cavp_vectors_match",
            "fn official_nist_cavp_monte_carlo_count_zero_matches",
            "fn official_million_a_vector_matches",
            "fn every_padding_boundary_matches_independent_expected_results",
            "fn every_split_and_chunk_width_matches_one_shot",
            "fn trait_api_length_domain_and_algorithm_identity_are_exact",
            "for _ in 0..1_000",
            "for split in 0..=message.len()",
            "for width in 1..=message.len()",
            "assert_ne!",
        ):
            require(algorithm_text, token, f"{name} tests")
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
    family_accelerated = root / SHA2_ACCEL_TEST
    if not family_accelerated.is_file() or family_accelerated.is_symlink():
        fail("accelerated SHA-2 family tests must be a regular file")
    family_text = family_accelerated.read_text(encoding="utf-8")
    if len(family_text.splitlines()) > 500:
        fail("accelerated SHA-2 family tests exceed 500 lines")
    for token in (
        "fn sha256_family_backend_matches_both_algorithm_identities",
        "fn sha512_family_backend_matches_all_four_algorithm_identities",
        "Sha256BackendSession::for_compiled_target()",
        "Sha512BackendSession::for_compiled_target()",
        "state512_224.update_with_backend(chunk, &backend)",
        "state512_256.finalize_with_backend(&backend)",
    ):
        require(family_text, token, "accelerated SHA-2 family tests")
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
