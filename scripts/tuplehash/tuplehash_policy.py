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
    "hardened_in_place.rs", "hardened_in_place/backend.rs",
    "hardened_in_place/core_state.rs", "hardened_in_place/fixed.rs",
    "hardened_in_place/reader.rs", "hardened_in_place/xof.rs",
    "hardened_in_place/accelerated.rs", "hardened_in_place/accelerated/backend.rs",
    "hardened_in_place/accelerated/fixed.rs", "hardened_in_place/accelerated/xof.rs",
))
TESTS = (CRATE / "tests/api.rs", CRATE / "tests/official_vectors.rs",
         CRATE / "src/hardened_in_place/tests.rs",
         CRATE / "src/hardened_in_place/core_state/tests.rs",
         CRATE / "src/hardened_in_place/reader/tests.rs",
         CRATE / "src/hardened_in_place/xof/tests.rs")
MANIFEST = CRATE / "Cargo.toml"
README = CRATE / "README.md"
CRYPTO = Path("crates/brynja-crypto/src/lib.rs")
MAIN = Path("crates/brynja/src/lib.rs")
PACKAGE_POLICY = Path("package-policy.toml")
CHECKS = Path("scripts/checks.sh")
DIFFERENTIAL = Path("scripts/tuplehash/check-tuplehash-differential.py")
DIFFERENTIAL_FIXTURE = Path("assurance/tuplehash-differential/src/main.rs")
SCOPED_FIXTURE = Path("assurance/tuplehash-differential/src/scoped.rs")
DIFFERENTIAL_MANIFEST = Path("assurance/tuplehash-differential/Cargo.toml")
PUBLIC_FIXTURE = Path("assurance/tuplehash-public-api/src/lib.rs")
PUBLIC_MANIFEST = Path("assurance/tuplehash-public-api/Cargo.toml")
CODEGEN = Path("scripts/tuplehash/check-tuplehash-codegen.sh")
MIRI = Path("scripts/zeroization/check-zeroization-miri.sh")
SANITIZER = Path("scripts/zeroization/check-zeroization-sanitizer.sh")
FILES = (*SOURCES, *TESTS, MANIFEST, README, CRYPTO, MAIN, PACKAGE_POLICY,
         CHECKS, DIFFERENTIAL, DIFFERENTIAL_FIXTURE, DIFFERENTIAL_MANIFEST,
         PUBLIC_FIXTURE, PUBLIC_MANIFEST, CODEGEN, MIRI, SANITIZER, SCOPED_FIXTURE)
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


def validate_encoding(text: str) -> None:
    code = without_comments(text).split("#[cfg(test)]", 1)[0]
    for token in (
        "pub(crate) const fn empty() -> Self",
        "fn left(&mut self, value: u128) -> Result<(), TupleHashError>",
        "fn right(&mut self, value: u128) -> Result<(), TupleHashError>",
        "if !(2..=17).contains(&length)",
        "clear_owned_region(&mut self.bytes)",
        "clear_owned_region(&mut self.length)",
    ):
        require(code, token, "borrowed secret encoding")
    if "Result<Self" in code or code.count("self.reset();") != 2:
        fail("secret encoding must reuse cleared storage without returning a populated owner")


def validate(root: Path) -> None:
    actual = set((root / CRATE / "src").glob("*.rs"))
    actual.update((root / CRATE / "src/hardened_in_place").rglob("*.rs"))
    expected = {root / source for source in SOURCES}
    expected.update(root / source for source in TESTS if "hardened_in_place" in source.parts)
    if actual != expected:
        fail("TupleHash production source inventory changed")
    loaded = {path: read(root, path) for path in FILES}
    hashed = (*SOURCES, *TESTS, PUBLIC_FIXTURE, PUBLIC_MANIFEST,
              DIFFERENTIAL_FIXTURE, DIFFERENTIAL_MANIFEST, DIFFERENTIAL,
              CODEGEN, SCOPED_FIXTURE)
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

    validate_scoped(loaded)

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
        "let mut prefix = SecretEncodedInteger::empty();", "prefix.left(bits)?;",
        "let mut suffix = SecretEncodedInteger::empty();", "suffix.right(output_bits)?;",
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
    validate_encoding(encoding)
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
    if manifest.get("features") != {"default": [],
        "hardened-execution": ["brynja-hash-sha3/hardened-execution"],
        "runtime-execution": ["hardened-execution", "brynja-hash-sha3/runtime-execution"]}:
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
        (MAIN, "four TupleHash"),
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
        (CODEGEN, "borrowed encoding writer result"),
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
    if loaded[MIRI].count("-p brynja-hash-tuple") != 4:
        fail("TupleHash Miri command inventory changed")
    if loaded[SANITIZER].count("-p brynja-hash-tuple") != 3:
        fail("TupleHash sanitizer command inventory changed")
    for path, expected_hash in HASHES.items():
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected_hash:
            fail(f"TupleHash reviewed source changed: {path}")


SCOPED_TOKENS = {
    "hardened_in_place/fixed.rs": (
        "sponge: cshake::$storage", "metadata: Metadata", "let cleanup = Guard(&mut self.metadata);",
        "Core::new(state, &mut *cleanup.0)", "impl for<'scope> FnOnce($state<'scope>) -> R",
        'bytes_input(b"TupleHash")?', "self.core.begin(bits)?;", "self.core.complete()?;",
        "if !self.complete { self.core.cancel(); }", "TupleHashPublicDeclassification",
        "pub fn finalize_secret<'out>(self,", "pub fn cancel(self)",
    ),
    "hardened_in_place/core_state.rs": (
        "state: Option<S>", "cleanup: Guard<'scope>", "self.core.cancel();",
        "self.state = None;", "self.cleanup.0.wipe();", "self.0.wipe();",
        "total\n            .checked_add(bits)", "core.phase(1)?;", "core.phase(2)?;", "self.phase(1)?;",
        "if read(&core.cleanup.0.remaining) != 0", "core.cleanup.0.phase = [2];",
        "core.cleanup.0.phase = [1];", "prefix.left(bits)?;", "suffix.right(bits)?;",
        "self\n            .state\n            .take()", "clear_owned_region(bytes)",
        "for chunk in input.chunks(168)", "Fips202BitString::new(&self.cleanup.0.pending, valid)",
        "self.finish(0)",
    ),
    "hardened_in_place/backend.rs": (
        "State for api::$state<'scope>", "self.finalize_bits_xof(tail)",
        "self.squeeze_final_bits_secret(", "Fips202Output::new(output, valid)", "Sha3PublicDeclassification::acknowledge()",
        "self.squeeze_public(output,", "self.squeeze_secret(output)",
    ),
    "hardened_in_place/xof.rs": (
        "inner: fixed::$fixed_workspace", "inner: fixed::$fixed_state<'scope>",
        "impl for<'scope> FnOnce($state<'scope>) -> R", "self.inner.begin_item(bits)",
        "self.inner.core.finish_xof()?", "Output::new(reader, cleanup)",
        "inner: Output<'scope, cshake::$backend_reader<'scope>>",
        "pub fn squeeze_public(&mut self,", "_authority: TupleHashPublicDeclassification",
        "pub fn squeeze_final_bits_secret<'out>(self,", "pub fn cancel(self)",
    ),
    "hardened_in_place/reader.rs": (
        "reader: Option<R>", "cleanup: Guard<'scope>", "if !self.complete {",
        "*self.reader = None;", "self.metadata.wipe();", "clear_owned_region(output)",
        ".read_public(output)?", ".read_secret(output)?", "guard.complete = true;",
        "self.reader.take().ok_or(TupleHashError::StateConsumed)?",
        "Fips202Output::new(output, valid)", ".map(TupleHashSecretOutput::new)",
    ),
    "hardened_in_place/accelerated.rs": (
        "struct Scratch<'a>(&'a mut [u8])", "brynja_core::clear_owned_region(self.0)",
    ),
    "hardened_in_place/accelerated/fixed.rs": (
        "sponge: cshake::$storage<'authority>", "metadata: Metadata", "stage: [u8; 168]",
        "pub fn new(session: KeccakSession<'authority>)", "cshake::$storage::new(session)?",
        "impl for<'scope> FnOnce($state<'scope, 'authority>) -> R",
        "let cleanup = Guard(metadata);", "let scratch = Scratch(scratch);",
        'sponge.with_bits(bytes_input(b"TupleHash")?',
        "Core::new(Backend { state, scratch: &mut *scratch.0 }, &mut *cleanup.0)",
        "self.core.begin(bits)?;", "self.core.complete()?;", "if !self.complete { self.core.cancel(); }",
        "TupleHashPublicDeclassification", "self.core.secret(output, valid)",
    ),
    "hardened_in_place/accelerated/xof.rs": (
        "inner: fixed::$fixed_workspace<'authority>", "inner: fixed::$fixed_state<'scope, 'authority>",
        "pub fn new(session: KeccakSession<'authority>)", "fixed::$fixed_workspace::new(session)?",
        "impl for<'scope> FnOnce($state<'scope, 'authority>) -> R",
        "self.inner.core.finish_xof()?", "Output::new(reader, cleanup)",
        "inner: Output<'scope, Backend<cshake::$backend_reader<'scope, 'authority>, &'scope mut [u8]>>",
        "self.inner.begin_item(bits)", "_authority: TupleHashPublicDeclassification",
        "pub fn squeeze_final_bits_secret<'out>(self,", "pub fn cancel(self)",
    ),
    "hardened_in_place/accelerated/backend.rs": (
        "State for Backend<cshake::$state<'s, 'a>, &'s mut [u8]>",
        "self.state.update(bytes)", "state: self.state.finalize_bits_xof(tail)?",
        "scratch: self.scratch", ".squeeze_public_with_scratch(",
        ".squeeze_final_bits_public(", ".squeeze_final_bits_secret(output, valid)",
        "Sha3PublicDeclassification::acknowledge()",
    ),
}


def validate_scoped(loaded: dict) -> None:
    for name, tokens in SCOPED_TOKENS.items():
        code = without_comments(loaded[CRATE / "src" / name])
        for token in tokens:
            require(code, token, "scoped tuple ownership/encoding")
    core = loaded[CRATE / "src/hardened_in_place/core_state.rs"]
    for field in ("pending", "used", "items", "remaining", "input_bits", "phase", "staging"):
        require(core, f"clear_owned_region(&mut self.{field})", "scoped tuple owned region")
    fixed = without_comments(loaded[CRATE / "src/hardened_in_place/fixed.rs"] +
                             loaded[CRATE / "src/hardened_in_place/xof.rs"] +
                             loaded[CRATE / "src/hardened_in_place/accelerated/fixed.rs"] +
                             loaded[CRATE / "src/hardened_in_place/accelerated/xof.rs"])
    for forbidden in ("pub fn item_count", "pub fn remaining_bits", "pub fn check_additional", "pub fn input_bits"):
        if forbidden in fixed:
            fail("scoped tuple exposes metadata/preflight query: " + forbidden)
    for token in ('scoped::check(',):
        require(loaded[DIFFERENTIAL_FIXTURE], token, "scoped tuple oracle dispatch")
    for token in ('TupleHash128Workspace', 'TupleHash256Workspace', 'TupleHashXof128Workspace',
                  'TupleHashXof256Workspace', 'scoped public/oracle mismatch', 'scoped secret/oracle mismatch'):
        require(loaded[SCOPED_FIXTURE], token, "scoped tuple differential coverage")
