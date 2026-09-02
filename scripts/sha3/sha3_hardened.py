#!/usr/bin/env python3
"""Validate the complete v0.24.10 hardened FIPS 202 boundary."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OWNER = Path("crates/brynja-hash-sha3/src/hardened/owner.rs")
API = Path("crates/brynja-hash-sha3/src/hardened/mod.rs")
FIXED = Path("crates/brynja-hash-sha3/src/hardened/fixed.rs")
XOF = Path("crates/brynja-hash-sha3/src/hardened/xof.rs")
OUTPUT = Path("crates/brynja-hash-sha3/src/hardened/output.rs")
SPONGE = Path("crates/brynja-hash-sha3/src/hardened/sponge.rs")
PERMUTATION = Path("crates/brynja-hash-sha3/src/hardened/permutation.rs")
TEST = Path("crates/brynja-hash-sha3/tests/hardened.rs")
LIB = Path("crates/brynja-hash-sha3/src/lib.rs")
CRYPTO = Path("crates/brynja-crypto/src/lib.rs")
FACADE = Path("crates/brynja/src/lib.rs")
CHECKS = Path("scripts/checks.sh")
CODEGEN = Path("scripts/sha3/check-sha3-hardened-codegen.sh")
FIXTURE_MANIFEST = Path("assurance/sha3-hardened-api/Cargo.toml")
FIXTURE_LOCK = Path("assurance/sha3-hardened-api/Cargo.lock")
FIXTURE_LIB = Path("assurance/sha3-hardened-api/src/lib.rs")
MIRI = Path("scripts/zeroization/check-zeroization-miri.sh")
SANITIZER = Path("scripts/zeroization/check-zeroization-sanitizer.sh")
FILES = (
    OWNER, API, FIXED, XOF, OUTPUT, SPONGE, PERMUTATION, TEST, LIB, CRYPTO,
    FACADE, CHECKS, CODEGEN, FIXTURE_MANIFEST, FIXTURE_LOCK, FIXTURE_LIB,
    MIRI, SANITIZER,
)


class HardenedPolicyError(RuntimeError):
    """The hardened FIPS 202 boundary differs from reviewed policy."""


def fail(message: str) -> None:
    raise HardenedPolicyError(message)


def read(root: Path, relative: Path) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        fail(f"hardened FIPS 202 input is not a regular file: {relative}")
    text = path.read_text(encoding="utf-8")
    if len(text.splitlines()) > 500:
        fail(f"hardened FIPS 202 source exceeds 500 lines: {relative}")
    return text


def require(text: str, token: str, label: str) -> None:
    if token not in text:
        fail(f"{label} drift: {token}")


def validate(root: Path = ROOT) -> None:
    loaded = {path: read(root, path) for path in FILES}
    owner = loaded[OWNER]
    fields = (
        "sponge_lanes", "partial_input", "message_length", "output_length",
        "phase", "suffix_staging", "padding_block", "squeeze_staging",
        "permutation_columns", "permutation_theta", "permutation_rearranged",
    )
    for field in fields:
        require(owner, f"pub(crate) {field}: [u8;", "owned secret region")
        require(owner, f"clear_owned_region(&mut self.{field})", "owner cleanup")
    require(owner, "impl<const RATE: usize> Drop for HardenedFips202Owner", "terminal cleanup")
    require(owner, "self.wipe();", "terminal cleanup")

    api = loaded[API]
    for identity in (
        "HardenedSha3_224", "HardenedSha3_256", "HardenedSha3_384",
        "HardenedSha3_512", "HardenedShake128", "HardenedShake128Reader",
        "HardenedShake256", "HardenedShake256Reader",
    ):
        require(api, identity, "hardened public identity")
    require(api, "pub trait HardenedFips202State: sealed::Registered", "sealed state capability")
    require(api, "HardenedFips202State + sealed::Construction", "sealed construction capability")

    fixed = loaded[FIXED]
    xof = loaded[XOF]
    for token in (
        "pub fn finalize_public(", "pub fn finalize_secret<'output>(",
        "pub fn finalize_bits_public(", "pub fn finalize_bits_secret<'output>(",
    ):
        require(fixed, token, "fixed hardened output API")
    for token in (
        "pub fn finalize_xof(", "pub fn finalize_bits_xof(",
        "pub fn squeeze_public(", "pub fn squeeze_secret<'output>(",
        "pub fn squeeze_final_bits_public(", "pub fn squeeze_final_bits_secret<'output>(",
    ):
        require(xof, token, "hardened XOF API")
    for forbidden in (
        "unsafe {", "unsafe fn", "extern \"C\"", "Vec<", "Box<",
        "update_with_backend", "BackendSession",
    ):
        if any(forbidden in loaded[path] for path in (OWNER, API, FIXED, XOF, OUTPUT, SPONGE, PERMUTATION)):
            fail(f"hardened FIPS 202 crossed a forbidden boundary: {forbidden}")
    operational = (API, FIXED, XOF, OUTPUT, SPONGE, PERMUTATION)
    for path in operational:
        source = loaded[path]
        for forbidden in ("to_le_bytes()", "from_le_bytes(", "<[u8;"):
            if forbidden in source:
                fail(f"hardened FIPS 202 created a byte-array temporary: {path}: {forbidden}")
        if re.search(r"=\s*\[", source):
            fail(f"hardened FIPS 202 created an array expression outside its owner: {path}")

    output = loaded[OUTPUT]
    require(output, "SecretRegionInitialization::begin(destination)", "typed secret output")
    require(output, "OwnedSecretRegion<'output>", "typed secret ownership")
    test = loaded[TEST]
    for token in (
        "every_fixed_identity_matches_the_ordinary_algorithm",
        "every_rate_and_multiblock_boundary_matches",
        "every_fixed_secret_output_transfers_and_clears",
        "both_xofs_match_across_irregular_absorb_and_squeeze_boundaries",
        "xof_secret_fragments_transfer_and_clear_independently",
        "every_partial_bit_width_matches_every_fixed_identity",
        "bit_input_and_bit_output_match_both_ordinary_xofs",
        "every_partial_secret_xof_width_matches_and_clears",
        "fixed_output_failure_is_atomic_by_classification",
        "recoverable_unwind_clears_typed_secret_destination",
        "cancel_and_early_drop_cover_absorber_and_reader_lifecycles",
    ):
        require(test, token, "hardened acceptance")
    require(loaded[LIB], "FIPS202_HARDENED_STATE_IMPLEMENTED: bool = true", "leaf claim")
    require(loaded[CRYPTO], "FIPS202_HARDENED_STATE_IMPLEMENTED: bool = true", "crypto claim")
    require(loaded[FACADE], "super::crypto::FIPS202_HARDENED_STATE_IMPLEMENTED", "facade claim")
    require(loaded[CHECKS], "python3 scripts/sha3/check-sha3-hardened.py", "repository gate")
    require(loaded[CHECKS], "scripts/sha3/check-sha3-hardened-codegen.sh", "codegen gate")
    require(loaded[FIXTURE_LIB], "#![no_std]", "downstream no_std fixture")
    require(loaded[FIXTURE_LIB], "exercise_all", "downstream all-identity fixture")
    require(loaded[MIRI], "--test hardened", "Miri hardened-state coverage")
    require(loaded[SANITIZER], "-p brynja-hash-sha3", "sanitizer package coverage")
    require(loaded[SANITIZER], "--tests", "sanitizer test coverage")


def run_acceptance() -> str:
    commands = (
        ["cargo", "test", "--locked", "-p", "brynja-hash-sha3", "--test", "hardened"],
        ["cargo", "test", "--locked", "--manifest-path", str(FIXTURE_MANIFEST)],
        [
            "cargo", "check", "--locked", "--manifest-path", str(FIXTURE_MANIFEST),
            "--target", "thumbv7em-none-eabi",
        ],
    )
    output = []
    for command in commands:
        result = subprocess.run(
            command, cwd=ROOT, check=False, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, timeout=240,
        )
        if result.returncode != 0:
            fail(f"hardened FIPS 202 acceptance failed:\n{result.stdout}")
        output.append(result.stdout)
    return "".join(output)
