#!/usr/bin/env python3
"""Validate the complete reviewed KMAC/KMACXOF boundary."""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

import kmac_reviewed_hashes


CRATE = Path("crates/brynja-mac-kmac")
SOURCES = tuple(CRATE / "src" / name for name in (
    "backend.rs", "core_state.rs", "error.rs", "fixed.rs", "lib.rs",
    "output.rs", "packer.rs", "policy.rs", "verify.rs", "xof.rs",
))
TESTS = (CRATE / "tests/api.rs", CRATE / "tests/official_vectors.rs")
MANIFEST = CRATE / "Cargo.toml"
README = CRATE / "README.md"
CRYPTO = Path("crates/brynja-crypto/src/lib.rs")
MAIN = Path("crates/brynja/src/lib.rs")
HARDENED_CSHAKE = Path("crates/brynja-hash-sha3/src/hardened/cshake.rs")
PACKAGE_POLICY = Path("package-policy.toml")
CHECKS = Path("scripts/checks.sh")
DIFFERENTIAL = Path("scripts/kmac/check-kmac-differential.py")
DIFFERENTIAL_FIXTURE = Path("assurance/kmac-differential/src/main.rs")
DIFFERENTIAL_MANIFEST = Path("assurance/kmac-differential/Cargo.toml")
PUBLIC_FIXTURE = Path("assurance/kmac-public-api/src/lib.rs")
CONFORMANCE_GATE = Path("scripts/kmac/check-kmac-conformance-gate.sh")
CONFORMANCE_FIXTURE = Path("assurance/kmac-conformance-rejected/src/lib.rs")
CONFORMANCE_MANIFEST = Path("assurance/kmac-conformance-rejected/Cargo.toml")
CODEGEN = Path("scripts/kmac/check-kmac-codegen.sh")
TIMING = Path("scripts/kmac/check-kmac-timing.sh")
TAG_GATE = Path("scripts/tag_gate.sh")
MIRI = Path("scripts/zeroization/check-zeroization-miri.sh")
SANITIZER = Path("scripts/zeroization/check-zeroization-sanitizer.sh")
FILES = (*SOURCES, *TESTS, MANIFEST, README, CRYPTO, MAIN, PACKAGE_POLICY,
         CHECKS, DIFFERENTIAL, DIFFERENTIAL_FIXTURE, DIFFERENTIAL_MANIFEST,
         PUBLIC_FIXTURE, CONFORMANCE_GATE, CONFORMANCE_FIXTURE,
         CONFORMANCE_MANIFEST, HARDENED_CSHAKE, CODEGEN, TIMING, TAG_GATE,
         MIRI, SANITIZER)
HASHES = {Path(path): digest for path, digest in kmac_reviewed_hashes.REVIEWED_HASHES.items()}


class KmacPolicyError(RuntimeError):
    """The reviewed KMAC boundary differs from policy."""


def fail(message: str) -> None:
    raise KmacPolicyError(message)


def read(root: Path, relative: Path) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        fail(f"KMAC boundary must be a regular file: {relative}")
    text = path.read_text(encoding="utf-8")
    if relative.suffix in {".rs", ".py"} and len(text.splitlines()) > 500:
        fail(f"KMAC boundary exceeds 500 lines: {relative}")
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
        fail("KMAC production source inventory changed")
    loaded = {path: read(root, path) for path in FILES}
    if set(HASHES) != set((*SOURCES, *TESTS, PUBLIC_FIXTURE,
                           DIFFERENTIAL_FIXTURE, DIFFERENTIAL_MANIFEST,
                           CONFORMANCE_GATE, CONFORMANCE_FIXTURE,
                           CONFORMANCE_MANIFEST, HARDENED_CSHAKE, CODEGEN,
                           DIFFERENTIAL)):
        fail("KMAC reviewed hash inventory changed")
    production = "\n".join(without_comments(loaded[path]) for path in SOURCES)
    for forbidden in (
        "unsafe", 'extern "C"', "std::", "alloc::", "Vec<", "Box<",
        "static mut", "Atomic", "thread_local", "core::arch", "asm!",
        "HardenedCshake128Reader::new", "Cshake128::new", "Cshake256::new",
        "impl Clone for Kmac", "impl Debug for Kmac", "impl Eq for KmacTag",
    ):
        if forbidden in production:
            fail(f"KMAC crossed forbidden boundary: {forbidden}")

    library = loaded[CRATE / "src/lib.rs"]
    for token in (
        "#![no_std]", "pub const KMAC_IMPLEMENTED: bool = true;",
        "pub use fixed::{Kmac128, Kmac256};",
        "KmacXof128, KmacXof128Reader, KmacXof256, KmacXof256Reader",
        "pub fn kmac128", "pub fn kmac256", "pub fn kmac128_bits",
        "pub fn kmac256_bits", "pub fn kmacxof128_secret",
        "pub fn kmacxof256_secret", "pub fn kmacxof128_public",
        "pub fn kmacxof256_public", "_conformance",
    ):
        require(library, token, "KMAC package")

    backend = loaded[CRATE / "src/backend.rs"]
    for token in (
        "HardenedCshake128", "HardenedCshake256", "b\"KMAC\"",
        "Sha3PublicDeclassification::acknowledge()",
        "fn finalize_xof_erasing_source(&mut self)",
        "fn finalize_bits_xof_erasing_source(",
        "fn wipe_in_place(&mut self)",
    ):
        require(backend, token, "hardened cSHAKE backend")
    packer = loaded[CRATE / "src/packer.rs"]
    for token in (
        "SecretEncodedInteger::left_encode(key_bits)", "finish_bytepad(rate)",
        "right_encode_u128(output_bits)", "clear_owned_region(&mut self.pending)",
        "clear_owned_region(&mut self.used)",
        "clear_owned_region(&mut self.emitted)",
        "impl Drop for SecretEncodedInteger",
        "impl<S: CshakeState> Drop for SecretPacker",
        "fn as_bytes(&self) -> Result<&[u8], KmacError>",
        "self.bytes.get(..length).ok_or(KmacError::SecretMemory)",
        "corrupt_encoded_width_fails_closed",
    ):
        require(packer, token, "KMAC key and trailer packing")
    if packer.count("clear_owned_region(&mut self.") != 9:
        fail("KMAC secret staging cleanup inventory changed")
    fixed = loaded[CRATE / "src/fixed.rs"]
    for token in (
        "finish_fixed(Some(final_message), bits, true)",
        "finish_fixed(Some(final_message), bits, false)",
        "verify_reader(reader, candidate)",
    ):
        require(fixed, token, "fixed KMAC API")
    core_state = loaded[CRATE / "src/core_state.rs"]
    require(core_state, "KmacError::TagTooShort", "KMAC strength policy")
    require(core_state, "state: S,", "KMAC inline owner")
    require(core_state, "append_right_encode(&mut self.state", "KMAC in-place transition")
    require(core_state, "self.state.wipe_in_place();", "KMAC in-place Drop cleanup")
    for forbidden in ("state: Option<S>", ".state.take()", "fn take_state"):
        if forbidden in core_state:
            fail(f"KMAC source owner can escape without in-place clearing: {forbidden}")
    hardened_cshake = loaded[HARDENED_CSHAKE]
    for token in (
        "pub fn finalize_xof_erasing_source(&mut self)",
        "pub fn finalize_bits_xof_erasing_source(",
        "pub fn wipe_in_place(&mut self)",
        "core::mem::replace(&mut self.owner",
        "self.owner.wipe();",
        "in_place_reader_transition_clears_exact_source_owner",
    ):
        require(hardened_cshake, token, "hardened cSHAKE source transition")
    output = loaded[CRATE / "src/output.rs"]
    for token in (
        "pub struct KmacTag", "pub struct KmacSecretOutput",
        "pub struct KmacVerification", "ct_eq", "clear_owned_region",
    ):
        require(output, token, "KMAC output boundary")
    if output.count("ct_eq") != 2:
        fail("KMAC constant-time comparison inventory changed")
    policy = loaded[CRATE / "src/policy.rs"]
    for token in (
        "FullStrength", "ConformanceOnly", "RiskManagedShort",
        "NonApproved", "#[kani::proof]",
    ):
        require(policy, token, "KMAC parameter policy")

    manifest = tomllib.loads(loaded[MANIFEST])
    if manifest.get("features") != {
        "default": [], "conformance-testing": [],
    }:
        fail("KMAC feature surface changed")
    if manifest.get("dependencies") != {
        "brynja-core": {"workspace": True},
        "brynja-hash-sha3": {"workspace": True},
    }:
        fail("KMAC dependency boundary changed")
    package = tomllib.loads(loaded[PACKAGE_POLICY]).get("packages", {}).get("brynja-mac-kmac")
    if package != {
        "class": "modern-shared", "publish": "crates-io",
        "required": ["brynja-core", "brynja-hash-sha3"], "optional": {},
        "features": ["conformance-testing"],
    }:
        fail("KMAC package classification changed")

    official = loaded[CRATE / "tests/official_vectors.rs"]
    for output_hex in (
        "E5780B0D3EA6F7D3", "B58618F71F92E1D5",
        "CD83740BBD92CCC8", "D5BE731C954ED773",
    ):
        require(official, output_hex, "official KMAC examples")
    api = loaded[CRATE / "tests/api.rs"]
    for token in (
        "production_and_conformance_parameter_domains_are_separate",
        "streaming_and_one_shot_are_identical_at_rate_boundaries",
        "domain_substitution_changes_outputs_and_fixed_is_not_xof_prefix",
        "verification_accepts_exact_tag_and_rejects_first_last_and_length_changes",
        "arbitrary_bits_are_canonical_and_streaming_xof_tracks_output",
        "secret_output_is_cleared_when_ownership_ends",
    ):
        require(api, token, "KMAC adversarial tests")
    if loaded[CRATE / "src/lib.rs"].count('#[cfg(feature = "conformance-testing")]') != 8:
        fail("KMAC one-shot conformance feature gate changed")
    if loaded[CRATE / "src/fixed.rs"].count('#[cfg(feature = "conformance-testing")]') != 7:
        fail("fixed KMAC conformance feature gate changed")
    if loaded[CRATE / "src/xof.rs"].count('#[cfg(feature = "conformance-testing")]') != 4:
        fail("KMACXOF conformance feature gate changed")
    differential_manifest = tomllib.loads(loaded[DIFFERENTIAL_MANIFEST])
    differential_dependency = differential_manifest["dependencies"]["brynja-mac-kmac"]
    if differential_dependency.get("features") != ["conformance-testing"]:
        fail("KMAC differential oracle lost explicit conformance feature")

    for path, token in (
        (CRYPTO, "KMAC_IMPLEMENTED: bool = true"),
        (MAIN, "four hardened KMAC/KMACXOF"),
        (PUBLIC_FIXTURE, "all_three_package_layers_are_operational"),
        (DIFFERENTIAL, "for index in range(64)"),
        (DIFFERENTIAL_FIXTURE, "MAX_CAMPAIGN_BYTES"),
        (CODEGEN, "KMAC source-owned state transitions and cleanup survive"),
        (TIMING, "assurance/kmac-timing/Cargo.toml"),
        (TAG_GATE, "scripts/kmac/check-kmac-timing.sh"),
        (MIRI, "-p brynja-mac-kmac"),
        (SANITIZER, "-p brynja-mac-kmac"),
        (CHECKS, "python3 scripts/kmac/check-kmac-differential.py"),
        (CHECKS, "scripts/kmac/check-kmac-conformance-gate.sh"),
        (CHECKS, "scripts/kmac/check-kmac-codegen.sh"),
        (CONFORMANCE_GATE, "default KMAC build unexpectedly exposed conformance constructors"),
        (CONFORMANCE_GATE, "assurance/kmac-differential/Cargo.toml"),
        (CONFORMANCE_FIXTURE, "Kmac128::new_conformance"),
        (CODEGEN, "Option<S>|state\\.take\\(\\)|take_state"),
        (CODEGEN, "take_reader_erasing_source"),
        (README, "no FIPS 140-3 validation"),
        (README, "Callers must reject candidate/tag lengths"),
    ):
        require(loaded[path], token, "KMAC evidence closure")
    require(
        loaded[SANITIZER],
        "-p brynja-mac-kmac \\\n    --tests \\\n    --target x86_64-unknown-linux-gnu",
        "KMAC AddressSanitizer command",
    )
    for path, expected_hash in HASHES.items():
        actual_hash = hashlib.sha256((root / path).read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            fail(f"KMAC reviewed source changed: {path}")
