#!/usr/bin/env python3
"""Validate the reviewed portable SHA-224/SHA-256/SHA-384/SHA-512 boundary."""

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
COMPRESS64 = Path("crates/brynja-hash-sha2/src/compress64.rs")
SHA512_STATE = Path("crates/brynja-hash-sha2/src/sha512_state.rs")
SHA384 = Path("crates/brynja-hash-sha2/src/sha384.rs")
SHA512 = Path("crates/brynja-hash-sha2/src/sha512.rs")
TEST = Path("crates/brynja-hash-sha2/tests/sha256.rs")
SHA224_TEST = Path("crates/brynja-hash-sha2/tests/sha224.rs")
SHA384_TEST = Path("crates/brynja-hash-sha2/tests/sha384.rs")
SHA512_TEST = Path("crates/brynja-hash-sha2/tests/sha512.rs")
ACCEL_TEST = Path("crates/brynja-hash-sha2/tests/sha256_accelerated.rs")
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
)
EXPECTED_SHA256 = {
    CORE_LIB: "4655d8df05873a89689af1250dfeab76b82ac05d165a92c99ff65565624c7827",
    LIB: "24ab43b388d18ea27536fca6cd377f06dce0465893382f1a438ab72bd4ac7275",
    COMPRESS: "d4229f08e40392976f354eaf81f5d5cd03069d5f3c497e2cf481f65a9848e4b1",
    DIGEST: "3b155ce93d7d48127372ffd1907fc9cbee86015be8fd8a433ffa835ddbaea5dd",
    ERROR: "fb50bc7e1aba37abb46993e79fd9fc5c59d17c90f9ff8ed3bf0a698ec8b8aaf9",
    SHA224: "69cebc10d3e94cc0fd57f5b45e9de406e04e1c6f2029ce668be520dbf40d7659",
    SHA256: "efbe3a588947e127dd0b0cecbe2b3e3b0a876a354d8d1f798052060d35ddb68d",
    COMPRESS64: "40edca2d80e9f60db4a9ea793fe5c61f79232012fb439025539e6b50c93f812b",
    SHA512_STATE: "658157733984dab954fd093184ed82cb435df6f44f74889835ccb9021afeaf53",
    SHA384: "2c1f20a07f8bb45350f0a875e9f4980178c8f940b1c1264c33709f0e28e637cb",
    SHA512: "bbf2af472f7cf8fcbad8ad78aafcf1cd94b1d764efba1172d5e6f3773c5c9991",
}
EXPECTED_TEST_SHA256 = {
    SHA224_TEST: "4a154a5293aa7fca5862fe1b383807998baa69b5eb5dd1ae2393b11d2c4fecb5",
    TEST: "c3eebf6ae0202321f72ddc131691720c94709e5281f905a5bd7d0fe4a603a3d1",
    ACCEL_TEST: "576c89cbbca4f0f45ce88efe750bd2976c5fa547becaae9fdbff103a38f66ae1",
    SHA384_TEST: "37bfa6cf7d73e4b4b15c6211f11bcdfeefcf8bd0ff44f5ddcd501ecf4ce0bf0e",
    SHA512_TEST: "2f7ed01daeac2e92d53a06fda04603e8e50a5a059c13c8212d2584c0f3a168eb",
}


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
        "pub fn sha224(input: &[u8]) -> Result<Sha224Digest, Sha224Error>",
        "pub fn sha256(input: &[u8]) -> Result<Sha256Digest, Sha256Error>",
        "pub fn sha384(input: &[u8]) -> Result<Sha384Digest, Sha384Error>",
        "pub fn sha512(input: &[u8]) -> Result<Sha512Digest, Sha512Error>",
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

    digest = sources[DIGEST][1]
    for token in (
        "pub struct $name([u8; Self::LENGTH]);",
        "pub const fn as_bytes(&self) -> &[u8; Self::LENGTH]",
        "pub const fn into_bytes(self) -> [u8; Self::LENGTH]",
        'digest_type!(Sha224Digest, 28, "SHA-224", "224");',
        'digest_type!(Sha256Digest, 32, "SHA-256", "256");',
        'digest_type!(Sha384Digest, 48, "SHA-384", "384");',
        'digest_type!(Sha512Digest, 64, "SHA-512", "512");',
    ):
        require(digest, token, "digest")

    error = sources[ERROR][1]
    require(error, "pub enum $name", "closed error")
    require(error, 'error_type!(Sha224Error, "SHA-224", "64");', "closed error")
    require(error, 'error_type!(Sha256Error, "SHA-256", "64");', "closed error")
    require(error, 'error_type!(Sha384Error, "SHA-384", "128");', "closed error")
    require(error, 'error_type!(Sha512Error, "SHA-512", "128");', "closed error")
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
