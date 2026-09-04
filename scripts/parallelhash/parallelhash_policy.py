#!/usr/bin/env python3
"""Validate the complete ParallelHash/ParallelHashXOF boundary."""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

import parallelhash_reviewed_hashes


PORTABLE = Path("crates/brynja-hash-parallel")
STD = Path("crates/brynja-hash-parallel-std")
SOURCES = tuple(PORTABLE / "src" / name for name in (
    "backend.rs", "core_state.rs", "error.rs", "fixed.rs", "lib.rs",
    "output.rs", "scheduled.rs", "xof.rs",
))
STD_SOURCES = (STD / "src/lib.rs",)
TESTS = (
    PORTABLE / "tests/api.rs", PORTABLE / "tests/official_vectors.rs",
    STD / "tests/executor.rs",
)
MANIFESTS = (PORTABLE / "Cargo.toml", STD / "Cargo.toml")
PUBLIC = (
    Path("assurance/parallelhash-public-api/Cargo.toml"),
    Path("assurance/parallelhash-public-api/src/lib.rs"),
    Path("assurance/parallelhash-std-public-api/Cargo.toml"),
    Path("assurance/parallelhash-std-public-api/src/lib.rs"),
)
DIFFERENTIAL = (
    Path("assurance/parallelhash-differential/Cargo.toml"),
    Path("assurance/parallelhash-differential/src/main.rs"),
    Path("scripts/parallelhash/check-parallelhash-differential.py"),
)
SUPPORT = (
    Path("crates/brynja-crypto/src/lib.rs"), Path("crates/brynja/src/lib.rs"),
    Path("package-policy.toml"), Path("scripts/checks.sh"),
    Path("scripts/zeroization/check-zeroization-miri.sh"),
    Path("scripts/zeroization/check-zeroization-sanitizer.sh"),
    Path("scripts/assurance/check-kani.sh"),
)
FILES = (*SOURCES, *STD_SOURCES, *TESTS, *MANIFESTS, *PUBLIC, *DIFFERENTIAL, *SUPPORT)
HASHED = (*SOURCES, *STD_SOURCES, *TESTS, *MANIFESTS, *PUBLIC, *DIFFERENTIAL)
HASHES = {Path(path): digest for path, digest in parallelhash_reviewed_hashes.REVIEWED_HASHES.items()}


class ParallelHashPolicyError(RuntimeError):
    """The reviewed ParallelHash boundary differs from policy."""


def fail(message: str) -> None:
    raise ParallelHashPolicyError(message)


def read(root: Path, path: Path) -> str:
    subject = root / path
    if not subject.is_file() or subject.is_symlink():
        fail(f"ParallelHash boundary must be a regular file: {path}")
    text = subject.read_text(encoding="utf-8")
    if path.suffix in {".rs", ".py"} and len(text.splitlines()) > 500:
        fail(f"ParallelHash boundary exceeds 500 lines: {path}")
    return text


def require(text: str, token: str, label: str) -> None:
    if token not in text:
        fail(f"{label} drift: {token}")


def validate(root: Path) -> None:
    expected_sources = {root / path for path in SOURCES}
    if set((root / PORTABLE / "src").glob("*.rs")) != expected_sources:
        fail("portable ParallelHash source inventory changed")
    loaded = {path: read(root, path) for path in FILES}
    if set(HASHES) != set(HASHED):
        fail("ParallelHash reviewed hash inventory changed")

    production = "\n".join(loaded[path] for path in SOURCES)
    for forbidden in (
        "unsafe", 'extern "C"', "std::", "alloc::", "Vec<", "Box<",
        "static mut", "Atomic", "thread_local", "core::arch", "asm!",
    ):
        if forbidden in production:
            fail(f"portable ParallelHash crossed forbidden boundary: {forbidden}")
    library = loaded[PORTABLE / "src/lib.rs"]
    for token in (
        "#![no_std]", "PARALLEL_HASH_IMPLEMENTED: bool = true",
        "pub fn parallel_hash128", "pub fn parallel_hash256",
        "pub fn parallel_hash_xof128", "pub fn parallel_hash_xof256",
        "#[kani::proof]",
    ):
        require(library, token, "portable API")
    backend = loaded[PORTABLE / "src/backend.rs"]
    for token in (
        'b"ParallelHash"', "HardenedCshake128", "HardenedCshake256",
        "LEAF_128_BYTES", "LEAF_256_BYTES", "impl Drop for BackendReader",
    ):
        require(backend, token, "SP 800-185 backend")
    core = loaded[PORTABLE / "src/core_state.rs"]
    for token in (
        "left_encode_u128", "right_encode_u128", "clear_owned_region",
        "checked_add", "finalize_input", "impl Drop for ParallelCore",
    ):
        require(core, token, "sequential lifecycle")
    scheduled = loaded[PORTABLE / "src/scheduled.rs"]
    for token in (
        "ParallelHash128Plan", "ParallelHash256Plan",
        "pub fn execute", "pub fn merge", "ParallelHashError::LeafOrder",
        "ParallelHashError::LeafIdentity", "core::ptr::eq(identity, self.identity)",
        "identity: &'plan PlanIdentity", "clear_owned_region(&mut self.merged)",
        "impl Drop for $collector",
    ):
        require(scheduled, token, "scheduled ownership")
    fixed = loaded[PORTABLE / "src/fixed.rs"]
    xof = loaded[PORTABLE / "src/xof.rs"]
    for name in ("ParallelHash128", "ParallelHash256", "HardenedParallelHash128", "HardenedParallelHash256"):
        require(fixed, name, "fixed identities")
    for name in ("ParallelHashXof128", "ParallelHashXof256", "HardenedParallelHashXof128", "HardenedParallelHashXof256"):
        require(xof, name, "XOF identities")

    portable_manifest = tomllib.loads(loaded[MANIFESTS[0]])
    if portable_manifest.get("features") != {"default": []}:
        fail("portable feature boundary changed")
    if portable_manifest.get("dependencies") != {
        "brynja-core": {"workspace": True},
        "brynja-hash-sha3": {"workspace": True},
    }:
        fail("portable dependency boundary changed")
    std_manifest = tomllib.loads(loaded[MANIFESTS[1]])
    if std_manifest.get("dependencies") != {
        "brynja-core": {"workspace": True},
        "brynja-hash-parallel": {"workspace": True},
    }:
        fail("std executor dependency boundary changed")
    std_source = loaded[STD_SOURCES[0]]
    for token in (
        "pub struct ParallelHashExecutor", "try_reserve_exact",
        "std::thread::scope", "CancellationToken", "WorkerPanicked",
        "struct LeafStorage", "clear_owned_region(leaf)", "join_worker(handle)",
        "failure.map_or(Ok(()), Err)",
        "pub fn parallel_hash128_bits", "pub fn parallel_hash256_bits",
        "pub fn parallel_hash_xof128_bits", "pub fn parallel_hash_xof256_bits",
    ):
        require(std_source, token, "native executor")
    for forbidden in ("HardenedCshake", "Keccak", "core::arch", 'extern "C"'):
        if forbidden in std_source:
            fail(f"std adapter contains cryptographic or native backend code: {forbidden}")

    official = loaded[PORTABLE / "tests/official_vectors.rs"]
    for token in (
        "all_six_official_fixed_examples_match",
        "all_six_official_xof_examples_match",
        "check128", "check256", "check_xof128", "check_xof256",
    ):
        require(official, token, "official NIST examples")
    api = loaded[PORTABLE / "tests/api.rs"]
    for token in (
        "streamed_scheduled_and_one_shot_are_identical",
        "empty_input_has_zero_leaves_and_b_one_is_valid",
        "reordered_leaf_permanently_fails_closed",
        "equal_shape_cross_plan_result_permanently_fails_closed",
        "arbitrary_bit_input_and_output_partition_are_stable",
        "hardened_output_and_workspace_clear_on_drop",
    ):
        require(api, token, "portable adversarial acceptance")
    executor_tests = loaded[STD / "tests/executor.rs"]
    for token in (
        "worker_counts_match_portable_fixed_and_xof",
        "arbitrary_bit_executor_matches_portable_fixed_and_xof",
        "cancellation_is_fail_closed_and_preserves_output",
    ):
        require(executor_tests, token, "executor acceptance")
    for path, token in (
        (PUBLIC[1], "leaf_crypto_main_scheduled_and_hardened_apis_are_operational"),
        (PUBLIC[3], "external_native_executor_is_operational"),
        (DIFFERENTIAL[2], "for index in range(64)"),
        (SUPPORT[0], "PARALLEL_HASH_IMPLEMENTED: bool = true"),
        (SUPPORT[1], "four ParallelHash identities"),
        (SUPPORT[3], "scripts/parallelhash/check-parallelhash-differential.py"),
        (SUPPORT[4], "-p brynja-hash-parallel"),
        (SUPPORT[5], "-p brynja-hash-parallel-std"),
        (SUPPORT[6], "cargo kani -p brynja-hash-parallel"),
    ):
        require(loaded[path], token, "ParallelHash evidence closure")
    for path, digest in HASHES.items():
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != digest:
            fail(f"ParallelHash reviewed source changed: {path}")
