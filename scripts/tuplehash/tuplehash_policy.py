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
    "lib.rs", "output.rs", "xof.rs",
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
        "finalize_bits_xof_erasing_source", "finalize_xof_erasing_source",
        "wipe_in_place", "squeeze_final_bits_secret",
    ):
        require(backend, token, "hardened cSHAKE backend")
    core = loaded[CRATE / "src/core_state.rs"]
    for token in (
        "left_encode_u128(bits)", "right_encode_u128(output_bits)",
        ".checked_add(added)", ".checked_add(1)",
        "self.backend.check_additional_bits", "self.backend.wipe();",
        "clear_owned_region(&mut self.pending)",
        "clear_owned_region(&mut self.items)", "impl Drop for TupleCore",
    ):
        require(core, token, "tuple encoding and cleanup")
    item = loaded[CRATE / "src/item.rs"]
    for token in (
        "pub struct TupleItemWriter", "remaining_bits", "pub fn finish",
        "TupleHashError::IncompleteItem", "self.core.abandon_item()",
        "impl Drop for TupleItemWriter",
    ):
        require(item, token, "affine tuple item")
    fixed = loaded[CRATE / "src/fixed.rs"]
    xof = loaded[CRATE / "src/xof.rs"]
    for token in ("TupleHash128", "TupleHash256", "HardenedTupleHash128", "HardenedTupleHash256"):
        require(fixed, token, "fixed TupleHash API")
    for token in ("TupleHashXof128", "TupleHashXof256", "HardenedTupleHashXof128", "HardenedTupleHashXof256"):
        require(xof, token, "TupleHashXOF API")
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
        "arbitrary_bit_items_and_outputs_are_canonical",
        "xof_partitions_and_hardened_output_match",
    ):
        require(api, token, "TupleHash adversarial tests")
    for path, token in (
        (CRYPTO, "TUPLE_HASH_IMPLEMENTED: bool = true"),
        (CRYPTO, "tuple_hash_xof128_bits"),
        (MAIN, "four TupleHash identities"),
        (PUBLIC_FIXTURE, "leaf_crypto_and_main_facades_are_operational"),
        (PUBLIC_FIXTURE, "brynja::crypto::tuple_hash_xof128_bits"),
        (DIFFERENTIAL, "for index in range(64)"),
        (DIFFERENTIAL_FIXTURE, "MAX_CAMPAIGN_BYTES"),
        (CODEGEN, "TupleHash source-owned state transitions and cleanup survive"),
        (MIRI, "-p brynja-hash-tuple"),
        (SANITIZER, "-p brynja-hash-tuple"),
        (CHECKS, "python3 scripts/tuplehash/check-tuplehash-differential.py"),
        (README, "no third-party dependency"),
    ):
        require(loaded[path], token, "TupleHash evidence closure")
    for path, expected_hash in HASHES.items():
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected_hash:
            fail(f"TupleHash reviewed source changed: {path}")
