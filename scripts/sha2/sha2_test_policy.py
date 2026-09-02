#!/usr/bin/env python3
"""Validate SHA-2 conformance, differential, and dynamic-analysis evidence."""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path
from typing import Callable


TEST = Path("crates/brynja-hash-sha2/tests/sha256.rs")
SHA224_TEST = Path("crates/brynja-hash-sha2/tests/sha224.rs")
SHA384_TEST = Path("crates/brynja-hash-sha2/tests/sha384.rs")
SHA512_TEST = Path("crates/brynja-hash-sha2/tests/sha512.rs")
SHA512_224_TEST = Path("crates/brynja-hash-sha2/tests/sha512_224.rs")
SHA512_256_TEST = Path("crates/brynja-hash-sha2/tests/sha512_256.rs")
ACCEL_TEST = Path("crates/brynja-hash-sha2/tests/sha256_accelerated.rs")
SHA2_ACCEL_TEST = Path("crates/brynja-hash-sha2/tests/sha2_accelerated.rs")
BIT_TEST = Path("crates/brynja-hash-sha2/tests/bit_inputs.rs")
BIT_VECTORS = Path("crates/brynja-hash-sha2/tests/vectors/nist-bit-selected.txt")
BIT_DIFFERENTIAL_MANIFEST = Path("assurance/sha2-bit-differential/Cargo.toml")
BIT_DIFFERENTIAL_LOCK = Path("assurance/sha2-bit-differential/Cargo.lock")
BIT_DIFFERENTIAL_MAIN = Path("assurance/sha2-bit-differential/src/main.rs")
BIT_DIFFERENTIAL_CHECK = Path("scripts/sha2/check-sha2-bit-differential.py")
MIRI_SCRIPT = Path("scripts/zeroization/check-zeroization-miri.sh")
SANITIZER_SCRIPT = Path("scripts/zeroization/check-zeroization-sanitizer.sh")
POLICY_SOURCE = Path("scripts/sha2/sha2_test_policy.py")
TEST_SOURCES = (
    TEST,
    SHA224_TEST,
    SHA384_TEST,
    SHA512_TEST,
    SHA512_224_TEST,
    SHA512_256_TEST,
    ACCEL_TEST,
    SHA2_ACCEL_TEST,
    BIT_TEST,
    BIT_VECTORS,
    BIT_DIFFERENTIAL_MANIFEST,
    BIT_DIFFERENTIAL_LOCK,
    BIT_DIFFERENTIAL_MAIN,
    BIT_DIFFERENTIAL_CHECK,
    MIRI_SCRIPT,
    SANITIZER_SCRIPT,
    POLICY_SOURCE,
)

Fail = Callable[[str], None]
Require = Callable[[str, str, str], None]


def checked_text(root: Path, relative: Path, label: str) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"{label} must be a regular file")
    text = path.read_text(encoding="utf-8")
    if len(text.splitlines()) > 500:
        raise RuntimeError(f"{label} exceeds 500 lines")
    return text


def validate_tests(
    root: Path,
    fail: Fail,
    require: Require,
    expected_hashes: dict[Path, str],
) -> None:
    try:
        text = checked_text(root, TEST, "SHA-256 tests")
    except RuntimeError as error:
        fail(str(error))
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

    try:
        sha224_text = checked_text(root, SHA224_TEST, "SHA-224 tests")
    except RuntimeError as error:
        fail(str(error))
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
        try:
            algorithm_text = checked_text(root, relative, f"{name} tests")
        except RuntimeError as error:
            fail(str(error))
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
        try:
            algorithm_text = checked_text(root, relative, f"{name} tests")
        except RuntimeError as error:
            fail(str(error))
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

    try:
        accelerated_text = checked_text(root, ACCEL_TEST, "accelerated SHA-256 tests")
    except RuntimeError as error:
        fail(str(error))
    for token in (
        "fn statically_proven_backend_matches_scalar_when_available",
        "Sha256BackendSession::for_compiled_target()",
        "for length in [0_usize, 1, 55, 56, 63, 64, 65, 127, 128, 192, 193]",
        "for width in 1..=67",
        "state.update_with_backend(chunk, &backend)",
    ):
        require(accelerated_text, token, "accelerated SHA-256 tests")

    try:
        family_text = checked_text(root, SHA2_ACCEL_TEST, "accelerated SHA-2 family tests")
    except RuntimeError as error:
        fail(str(error))
    for token in (
        "fn sha256_family_backend_matches_both_algorithm_identities",
        "fn sha512_family_backend_matches_all_four_algorithm_identities",
        "Sha256BackendSession::for_compiled_target()",
        "Sha512BackendSession::for_compiled_target()",
        "state512_224.update_with_backend(chunk, &backend)",
        "state512_256.finalize_with_backend(&backend)",
        "finalize_bits_with_backend(bits, &backend)",
    ):
        require(family_text, token, "accelerated SHA-2 family tests")

    try:
        bit_test = checked_text(root, BIT_TEST, "SHA-2 bit tests")
    except RuntimeError as error:
        fail(str(error))
    for token in (
        "selected_official_nist_bit_vectors_match_every_identity",
        "canonical_representation_rejects_every_ambiguous_tail_width",
        "byte_aligned_bit_apis_preserve_every_frozen_byte_api",
        "exact_bit_length_preflight_is_transactional_for_every_identity",
        "assert_eq!(count, 240)",
        "state.finalize_bits(tail)",
    ):
        require(bit_test, token, "SHA-2 bit tests")

    vectors = (root / BIT_VECTORS).read_text(encoding="utf-8")
    authority = "cd7b9f11680c6e0ccdbe13b28403f2017b5ff48789152162461e0a24fb4c5d45"
    if authority not in vectors:
        fail("NIST bit-vector authority hash changed")
    records = [line for line in vectors.splitlines() if line and not line.startswith("#")]
    if len(records) != 240:
        fail(f"NIST bit-vector selection changed: {len(records)}")
    algorithms = ("SHA224", "SHA256", "SHA384", "SHA512", "SHA512_224", "SHA512_256")
    for algorithm in algorithms:
        selected = [line for line in records if line.startswith(f"{algorithm}|")]
        residues = {int(line.split("|", 2)[1]) % 8 for line in selected}
        if len(selected) != 40 or residues != set(range(8)):
            fail(f"NIST bit-vector coverage changed: {algorithm}")

    differential_main = (root / BIT_DIFFERENTIAL_MAIN).read_text(encoding="utf-8")
    differential_check = (root / BIT_DIFFERENTIAL_CHECK).read_text(encoding="utf-8")
    dynamic_sources = (
        (differential_main, "bounded Rust differential adapter", (
            "MAX_INPUT_LINE_BYTES: usize = 1_200",
            "MAX_MESSAGE_BITS: usize = 4_096",
            "read_bounded_line(&mut reader, &mut buffer, line_number)",
            "input line exceeds bound",
            "BitString::new(&bytes, valid)",
            "try_reserve_exact(expected_bytes)",
            '"sha512_256" => hash!(sha512_256_bits)',
        )),
        (differential_check, "independent Python bit oracle", (
            "def padded(message: bytes, bit_len: int",
            "def digest32(",
            "def digest64(",
            "for algorithm_index, algorithm in enumerate(CONFIG)",
            "SHA-2 arbitrary-bit differential oracle: PASS",
        )),
    )
    for dynamic_text, label, tokens in dynamic_sources:
        if len(dynamic_text.splitlines()) > 500:
            fail(f"{label} exceeds 500 lines")
        for token in tokens:
            require(dynamic_text, token, label)
    if ".lines()" in differential_main:
        fail("bounded Rust differential adapter reads an unbounded line")

    manifest = tomllib.loads((root / BIT_DIFFERENTIAL_MANIFEST).read_text(encoding="utf-8"))
    if manifest.get("package", {}).get("publish") is not False:
        fail("bit differential adapter became publishable")
    if set(manifest.get("dependencies", {})) != {"brynja-hash-sha2"}:
        fail("bit differential adapter dependency graph changed")
    for relative, label in (
        (MIRI_SCRIPT, "SHA-2 Miri coverage"),
        (SANITIZER_SCRIPT, "SHA-2 AddressSanitizer coverage"),
    ):
        dynamic = (root / relative).read_text(encoding="utf-8")
        require(dynamic, "-p brynja-hash-sha2", label)
        require(dynamic, "--test bit_inputs", label)

    for relative, expected_hash in expected_hashes.items():
        digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if digest != expected_hash:
            fail(f"SHA-2 reviewed test hash drift: {relative}")
