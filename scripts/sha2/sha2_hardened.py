#!/usr/bin/env python3
"""Validate the complete v0.24.8 hardened SHA-2 boundary."""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OWNER = Path("crates/brynja-hash-sha2/src/hardened/owner.rs")
API = Path("crates/brynja-hash-sha2/src/hardened/mod.rs")
OUTPUT = Path("crates/brynja-hash-sha2/src/hardened/output.rs")
STATE32 = Path("crates/brynja-hash-sha2/src/hardened/state32.rs")
STATE64 = Path("crates/brynja-hash-sha2/src/hardened/state64.rs")
TEST = Path("crates/brynja-hash-sha2/tests/hardened.rs")
LIB = Path("crates/brynja-hash-sha2/src/lib.rs")
CRYPTO = Path("crates/brynja-crypto/src/lib.rs")
CHECKS = Path("scripts/checks.sh")
CODEGEN = Path("scripts/sha2/check-sha2-hardened-codegen.sh")
FIXTURE_MANIFEST = Path("assurance/sha2-hardened-api/Cargo.toml")
FIXTURE_LOCK = Path("assurance/sha2-hardened-api/Cargo.lock")
FIXTURE_LIB = Path("assurance/sha2-hardened-api/src/lib.rs")
MIRI = Path("scripts/zeroization/check-zeroization-miri.sh")
SANITIZER = Path("scripts/zeroization/check-zeroization-sanitizer.sh")
FILES = (
    OWNER, API, OUTPUT, STATE32, STATE64, TEST, LIB, CRYPTO, CHECKS, CODEGEN,
    FIXTURE_MANIFEST, FIXTURE_LOCK, FIXTURE_LIB, MIRI, SANITIZER,
)


class HardenedPolicyError(RuntimeError):
    """The hardened SHA-2 boundary differs from reviewed policy."""


def fail(message: str) -> None:
    raise HardenedPolicyError(message)


def read(root: Path, relative: Path) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        fail(f"hardened SHA-2 input is not a regular file: {relative}")
    text = path.read_text(encoding="utf-8")
    if len(text.splitlines()) > 500:
        fail(f"hardened SHA-2 source exceeds 500 lines: {relative}")
    return text


def require(text: str, token: str, label: str) -> None:
    if token not in text:
        fail(f"{label} drift: {token}")


def validate(root: Path = ROOT) -> None:
    loaded = {path: read(root, path) for path in FILES}
    owner = loaded[OWNER]
    fields = (
        "chaining_state", "partial_input", "message_length", "phase",
        "message_schedule", "block_copy", "padding_block", "output_staging",
    )
    for field in fields:
        require(owner, f"pub(crate) {field}: [u8;", "owned region")
        require(owner, f"clear_owned_region(&mut self.{field})", "owner cleanup")
    require(owner, "impl Drop for HardenedSha2Owner", "terminal cleanup")
    require(owner, "self.wipe();", "terminal cleanup")
    api = loaded[API]
    for identity in (
        "HardenedSha224", "HardenedSha256", "HardenedSha384",
        "HardenedSha512", "HardenedSha512_224", "HardenedSha512_256",
    ):
        require(api, identity, "hardened public identity")
    for token in (
        "pub trait HardenedSha2State: sealed::Registered",
        "PublicDeclassification",
    ):
        require(api, token, "hardened API")
    for method in (
        "pub fn finalize_public(", "pub fn finalize_secret<'output>(",
        "pub fn finalize_bits_public(", "pub fn finalize_bits_secret<'output>(",
    ):
        if api.count(method) != 2:
            fail(f"hardened API family coverage drift: {method}")
    if "update_with_backend" in api or "Sha256Backend" in api or "Sha512Backend" in api:
        fail("hardened SHA-2 API gained an accelerated path without cleanup evidence")
    for forbidden in ("unsafe {", "unsafe fn", "extern \"C\"", "Vec<", "Box<"):
        if any(forbidden in loaded[path] for path in (OWNER, API, OUTPUT, STATE32, STATE64)):
            fail(f"hardened SHA-2 crossed a forbidden boundary: {forbidden}")
    output = loaded[OUTPUT]
    require(output, "SecretRegionInitialization::begin(destination)?", "typed secret output")
    require(output, "clear_failed_secret_output", "failure cleanup")
    test = loaded[TEST]
    for token in (
        "every_hardened_identity_matches_the_ordinary_algorithm",
        "padding_and_multiblock_boundaries_match_all_ordinary_states",
        "every_secret_output_transfers_and_executes_clearing_duty",
        "recoverable_unwind_clears_typed_secret_destination",
        "public_output_failure_is_unchanged_and_secret_failure_is_cleared",
    ):
        require(test, token, "hardened acceptance")
    require(loaded[LIB], "SHA2_HARDENED_STATE_IMPLEMENTED: bool = true", "leaf claim")
    require(loaded[CRYPTO], "SHA2_HARDENED_STATE_IMPLEMENTED: bool = true", "facade claim")
    require(loaded[CHECKS], "python3 scripts/sha2/check-sha2-hardened.py", "repository gate")
    require(loaded[CHECKS], "scripts/sha2/check-sha2-hardened-codegen.sh", "codegen gate")
    require(loaded[FIXTURE_LIB], "#![no_std]", "downstream no_std fixture")
    require(loaded[FIXTURE_LIB], "exercise_all", "downstream all-identity fixture")
    require(loaded[MIRI], "--test hardened", "Miri hardened-state coverage")
    require(loaded[SANITIZER], "--test hardened", "sanitizer hardened-state coverage")


def run_acceptance() -> str:
    commands = (
        ["cargo", "test", "--locked", "-p", "brynja-hash-sha2", "--test", "hardened"],
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
            fail(f"hardened SHA-2 acceptance failed:\n{result.stdout}")
        output.append(result.stdout)
    return "".join(output)
