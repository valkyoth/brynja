#!/usr/bin/env python3
"""Validate the complete reviewed TupleHash/TupleHashXOF boundary."""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

import tuplehash_reviewed_hashes


CRATE = Path("crates/brynja-hash-tuple")
SOURCES = tuple(CRATE / "src" / name for name in (
    "backend.rs", "core_state.rs", "error.rs", "fixed.rs", "item.rs",
    "lib.rs", "output.rs", "secret_encoding.rs", "xof.rs",
))
TESTS = (CRATE / "tests/api.rs", CRATE / "tests/official_vectors.rs")
MANIFEST = CRATE / "Cargo.toml"
README = CRATE / "README.md"
CRYPTO = Path("crates/brynja-crypto/src/lib.rs")
MAIN = Path("crates/brynja/src/lib.rs")
PACKAGE_POLICY = Path("package-policy.toml")
CHECKS = Path("scripts/checks.sh")
DIFFERENTIAL = Path("scripts/tuplehash/check-tuplehash-differential.py")
DIFFERENTIAL_FIXTURE = Path("assurance/tuplehash-differential/src/main.rs")
DIFFERENTIAL_MANIFEST = Path("assurance/tuplehash-differential/Cargo.toml")
PUBLIC_FIXTURE = Path("assurance/tuplehash-public-api/src/lib.rs")
PUBLIC_MANIFEST = Path("assurance/tuplehash-public-api/Cargo.toml")
CODEGEN = Path("scripts/tuplehash/check-tuplehash-codegen.sh")
MIRI = Path("scripts/zeroization/check-zeroization-miri.sh")
SANITIZER = Path("scripts/zeroization/check-zeroization-sanitizer.sh")
FILES = (*SOURCES, *TESTS, MANIFEST, README, CRYPTO, MAIN, PACKAGE_POLICY,
         CHECKS, DIFFERENTIAL, DIFFERENTIAL_FIXTURE, DIFFERENTIAL_MANIFEST,
         PUBLIC_FIXTURE, PUBLIC_MANIFEST, CODEGEN, MIRI, SANITIZER)
HASHES = {Path(path): digest for path, digest in tuplehash_reviewed_hashes.REVIEWED_HASHES.items()}


class TupleHashPolicyError(RuntimeError):
    """The reviewed TupleHash boundary differs from policy."""


def fail(message: str) -> None:
    raise TupleHashPolicyError(message)


def read(root: Path, relative: Path) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        fail(f"TupleHash boundary must be a regular file: {relative}")
    text = path.read_text(encoding="utf-8")
    if relative.suffix in {".rs", ".py"} and len(text.splitlines()) > 500:
        fail(f"TupleHash boundary exceeds 500 lines: {relative}")
    return text


def require(text: str, token: str, label: str) -> None:
    if token not in text:
        fail(f"{label} drift: {token}")


def without_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def validate(root: Path) -> None:
    actual = set((root / CRATE / "src").glob("*.rs"))
    expected = {root / source for source in SOURCES}
    if actual != expected:
        fail("TupleHash production source inventory changed")
    loaded = {path: read(root, path) for path in FILES}
    hashed = (*SOURCES, *TESTS, PUBLIC_FIXTURE, PUBLIC_MANIFEST,
              DIFFERENTIAL_FIXTURE, DIFFERENTIAL_MANIFEST, DIFFERENTIAL,
              CODEGEN)
    if set(HASHES) != set(hashed):
        fail("TupleHash reviewed hash inventory changed")
    production = "\n".join(without_comments(loaded[path]) for path in SOURCES)
    for forbidden in (
        "unsafe", 'extern "C"', "std::", "alloc::", "Vec<", "Box<",
        "static mut", "Atomic", "thread_local", "core::arch", "asm!",
        "impl Clone for Tuple", "impl Debug for Tuple",
    ):
        if forbidden in production:
            fail(f"TupleHash crossed forbidden boundary: {forbidden}")

    library = loaded[CRATE / "src/lib.rs"]
    for token in (
        "#![no_std]", "pub const TUPLE_HASH_IMPLEMENTED: bool = true;",
        "pub fn tuple_hash128", "pub fn tuple_hash256",
        "pub fn tuple_hash128_bits", "pub fn tuple_hash256_bits",
        "pub fn tuple_hash_xof128", "pub fn tuple_hash_xof256",
        "pub fn tuple_hash_xof128_bits", "pub fn tuple_hash_xof256_bits",
    ):
        require(library, token, "TupleHash package")
    backend = loaded[CRATE / "src/backend.rs"]
    for token in (
        "HardenedCshake128", "HardenedCshake256", 'b"TupleHash"',
        "pub(crate) struct BackendReader<'a>",
        "backend: &'a mut Backend", "finalize_in_place(",
        "enter_squeezing_in_place(tail)?",
        "BackendStrength::Bits128", "BackendStrength::Bits256",
        "squeeze_final_bits_public_in_place",
        "squeeze_final_bits_secret_in_place", "match self.backend",
        "impl Drop for BackendReader<'_>", "self.backend.wipe();",
    ):
        require(backend, token, "hardened cSHAKE backend")
    core = loaded[CRATE / "src/core_state.rs"]
    for token in (
        "SecretEncodedInteger::left(bits)",
        "SecretEncodedInteger::right(output_bits)",
        ".checked_add(added)", ".checked_add(1)",
        "self.backend.check_additional_bits", "self.backend.wipe();",
        "self.failed = [1];", "write_u128(&mut self.remaining, bits)",
        "write_u128(&mut self.items, count)",
        "self.complete_item()", "checked_remaining_after(",
        "Fips202BitString::new(&self.pending, valid)",
        "clear_owned_region(&mut self.pending)",
        "clear_owned_region(&mut self.items)",
        "clear_owned_region(&mut self.remaining)", "finish_in_place(",
        "self.backend.finalize_in_place", "impl Drop for TupleCore",
    ):
        require(core, token, "tuple encoding and cleanup")
    finish_body = core.split("pub(crate) fn finish_in_place(", 1)[1].split(
        "pub(crate) fn abandon_item", 1
    )[0]
    for field in ("pending", "used", "items", "remaining", "failed"):
        require(
            finish_body,
            f"clear_owned_region(&mut self.{field})",
            "successful finalization metadata cleanup",
        )
    for forbidden in ("left_encode_u128(bits)", "right_encode_u128(output_bits)",
                      "let bytes = [", "let byte = self.pending", ".to_le_bytes()",
                      "u128::from_le_bytes"):
        if forbidden in core:
            fail(f"TupleHash created uncleared local staging: {forbidden}")
    item = loaded[CRATE / "src/item.rs"]
    for token in (
        "pub struct TupleItemWriter", "remaining_bits", "pub fn finish",
        "self.core.check_item_fragment(bits)?", "self.core.consume_item(bits)?",
        "self.core.complete_item()?", "self.core.abandon_item()",
        "impl Drop for TupleItemWriter",
    ):
        require(item, token, "affine tuple item")
    if "remaining: u128" in item or "self.remaining = 0" in item:
        fail("streamed item length escaped the clearing TupleCore owner")
    encoding = loaded[CRATE / "src/secret_encoding.rs"]
    for token in (
        "struct SecretEncodedInteger", "bytes: [u8; 17]", "length: [u8; 1]",
        "pub(crate) fn left", "pub(crate) fn right",
        "impl Drop for SecretEncodedInteger",
        "clear_owned_region(&mut self.bytes)",
        "clear_owned_region(&mut self.length)",
        "clearing_encoders_match_sp800185_for_boundary_values",
    ):
        require(encoding, token, "secret tuple-length encoding")
    fixed = loaded[CRATE / "src/fixed.rs"]
    xof = loaded[CRATE / "src/xof.rs"]
    for token in ("TupleHash128", "TupleHash256", "HardenedTupleHash128", "HardenedTupleHash256"):
        require(fixed, token, "fixed TupleHash API")
    for token in ("pub fn finalize(&mut self", "pub fn finalize_secret<'a>(\n                &mut self"):
        require(fixed, token, "borrowing fixed TupleHash lifecycle")
    for token in ("TupleHashXof128", "TupleHashXof256", "HardenedTupleHashXof128", "HardenedTupleHashXof256"):
        require(xof, token, "TupleHashXOF API")
    for token in ("pub fn finalize_xof(&mut self)", "pub struct $reader<'a>", "reader: BackendReader<'a>"):
        require(xof, token, "borrowing TupleHashXOF lifecycle")
    output = loaded[CRATE / "src/output.rs"]
    require(output, "TupleHashPublicDeclassification", "output classification")
    require(output, "HardenedSha3SecretOutput", "typed secret output")

    manifest = tomllib.loads(loaded[MANIFEST])
    if manifest.get("features") != {"default": []}:
        fail("TupleHash feature boundary changed")
    if manifest.get("dependencies") != {
        "brynja-core": {"workspace": True},
        "brynja-hash-sha3": {"workspace": True},
    }:
        fail("TupleHash dependency boundary changed")
    package = tomllib.loads(loaded[PACKAGE_POLICY]).get("packages", {}).get("brynja-hash-tuple")
    if package != {
        "class": "modern-shared", "publish": "crates-io",
        "required": ["brynja-core", "brynja-hash-sha3"], "optional": {},
    }:
        fail("TupleHash package classification changed")

    official = loaded[CRATE / "tests/official_vectors.rs"]
    for output_hex in ("C5D8786C1AFB9B82", "45000BE63F9B6BFD", "2F103CD7C3232035", "0C59B11464F2336C"):
        require(official, output_hex, "official TupleHash examples")
    api = loaded[CRATE / "tests/api.rs"]
    for token in (
        "tuple_boundaries_order_and_empty_items_are_distinct",
        "exact_length_streaming_matches_whole_items",
        "abandoned_or_incomplete_items_fail_closed",
        "forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch",
        "arbitrary_bit_items_and_outputs_are_canonical",
        "xof_partitions_and_hardened_output_match",
        "assert_eq!(whole.item_count(), 0)",
        "assert_eq!(ordinary.item_count(), 0)",
        "assert_eq!(hardened.item_count(), 0)",
        "assert_eq!(hardened_xof.item_count(), 0)",
    ):
        require(api, token, "TupleHash adversarial tests")
    for path, token in (
        (CRYPTO, "TUPLE_HASH_IMPLEMENTED: bool = true"),
        (CRYPTO, "tuple_hash_xof128_bits"),
        (MAIN, "four TupleHash identities"),
        (PUBLIC_FIXTURE, "leaf_crypto_and_main_facades_are_operational"),
        (PUBLIC_FIXTURE, "brynja::crypto::tuple_hash_xof128_bits"),
        (PUBLIC_FIXTURE, "finalize_hardened_public_in_place"),
        (PUBLIC_FIXTURE, "finalize_streaming_in_place"),
        (DIFFERENTIAL, "for index in range(64)"),
        (DIFFERENTIAL_FIXTURE, "MAX_CAMPAIGN_BYTES"),
        (CODEGEN, "TupleHash exact source and reader cleanup survives"),
        (CODEGEN, "assurance/tuplehash-public-api/Cargo.toml"),
        (CODEGEN, "reject_secret_copy"),
        (CODEGEN, "self_test_secret_copy_matcher"),
        (CODEGEN, "reject_any_memcpy"),
        (CODEGEN, "Backend17finalize_in_place"),
        (CODEGEN, "TupleCore15finish_in_place"),
        (MIRI, "-p brynja-hash-tuple"),
        (MIRI, "forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch"),
        (SANITIZER, "-p brynja-hash-tuple"),
        (SANITIZER, "forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch"),
        (CHECKS, "python3 scripts/tuplehash/check-tuplehash-differential.py"),
        (README, "no third-party dependency"),
    ):
        require(loaded[path], token, "TupleHash evidence closure")
    if loaded[MIRI].count("-p brynja-hash-tuple") != 2:
        fail("TupleHash Miri command inventory changed")
    if loaded[SANITIZER].count("-p brynja-hash-tuple") != 2:
        fail("TupleHash sanitizer command inventory changed")
    for path, expected_hash in HASHES.items():
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected_hash:
            fail(f"TupleHash reviewed source changed: {path}")
