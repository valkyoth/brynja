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
STD_SOURCES = (STD / "src/lib.rs", STD / "src/worker.rs")
EXECUTION = tuple(PORTABLE / "src/execution" / name for name in (
    "backend.rs", "binding.rs", "collector.rs", "collector/tests.rs", "encoding.rs", "mod.rs",
    "ownership.rs", "plan.rs", "stream.rs", "stream_output.rs", "stream/tests.rs",
))
STD_EXECUTION = tuple(STD / "src/execution" / name for name in (
    "mod.rs", "selection.rs", "worker.rs", "tests.rs", "worker/tests.rs",
))
TESTS = (
    PORTABLE / "tests/api.rs", PORTABLE / "tests/official_vectors.rs",
    STD / "tests/executor.rs",
    PORTABLE / "tests/execution.rs", PORTABLE / "tests/execution_vectors/mod.rs",
    PORTABLE / "tests/execution_stream.rs",
    STD / "tests/execution.rs",
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
    Path("assurance/parallelhash-differential/src/execution.rs"),
    Path("assurance/parallelhash-differential/src/lib.rs"),
    PORTABLE / "README.md", STD / "README.md",
    Path("scripts/parallelhash/check-parallelhash-execution-differential.py"),
    Path("scripts/parallelhash/check-parallelhash-execution-package.py"),
    Path("scripts/parallelhash/check-parallelhash-execution-codegen.py"),
    Path("scripts/parallelhash/parallelhash_cleanup.py"),
    Path("scripts/parallelhash/parallelhash_execution_native.py"),
    Path("scripts/parallelhash/capture-parallelhash-execution-native.py"),
    Path("scripts/parallelhash/check-parallelhash-execution-native.py"),
    Path("scripts/parallelhash/test-parallelhash-execution-native.py"),
)
SUPPORT = (
    Path("crates/brynja-crypto/src/lib.rs"), Path("crates/brynja/src/lib.rs"),
    Path("package-policy.toml"), Path("scripts/checks.sh"),
    Path("scripts/zeroization/check-zeroization-miri.sh"),
    Path("scripts/zeroization/check-zeroization-sanitizer.sh"),
    Path("scripts/assurance/check-kani.sh"),
)
OWNER_INVENTORY = Path("docs/parallelhash-execution.md")
FILES = (*SOURCES, *STD_SOURCES, *EXECUTION, *STD_EXECUTION, *TESTS, *MANIFESTS, *PUBLIC, *DIFFERENTIAL, *SUPPORT, OWNER_INVENTORY)
HASHED = (*SOURCES, *STD_SOURCES, *EXECUTION, *STD_EXECUTION, *TESTS, *MANIFESTS, *PUBLIC, *DIFFERENTIAL)
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
    expected_sources = {root / path for path in (*SOURCES, *EXECUTION)}
    if set((root / PORTABLE / "src").rglob("*.rs")) != expected_sources:
        fail("portable ParallelHash source inventory changed")
    expected_std_sources = {root / path for path in (*STD_SOURCES, *STD_EXECUTION)}
    if set((root / STD / "src").rglob("*.rs")) != expected_std_sources:
        fail("std ParallelHash source inventory changed")
    loaded = {path: read(root, path) for path in FILES}
    for owner in ("`backend::State`", "`Collector` metadata", "`Stream` workspace and metadata",
                  "`Encoded`", "`Leaf` / worker output", "`Clear` / output staging",
                  "`Reader` / `StreamReader`", "std `worker::Storage`"):
        require(loaded[OWNER_INVENTORY], owner, "execution secret-region inventory")
    require(loaded[STD / "src/execution/worker/tests.rs"],
            "storage_clear_visits_every_byte_of_every_live_slot", "std slot clearing test")
    if set(HASHES) != set(HASHED):
        fail("ParallelHash reviewed hash inventory changed")

    production = "\n".join(loaded[path] for path in (*SOURCES, *EXECUTION))
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
    if portable_manifest.get("features") != {
        "default": [],
        "hardened-execution": ["brynja-hash-sha3/hardened-execution"],
        "runtime-execution": ["hardened-execution", "brynja-hash-sha3/runtime-execution"],
    }:
        fail("portable feature boundary changed")
    if portable_manifest.get("dev-dependencies") != {
        "brynja-crypto-cpu": {"workspace": True, "features": ["hardened-execution"]},
        "brynja-crypto-cpu-std": {"workspace": True, "features": ["runtime-execution"]},
    }:
        fail("execution test-only authority dependencies changed")
    if portable_manifest.get("dependencies") != {
        "brynja-core": {"workspace": True},
        "brynja-hash-sha3": {"workspace": True},
    }:
        fail("portable dependency boundary changed")
    std_manifest = tomllib.loads(loaded[MANIFESTS[1]])
    if std_manifest.get("features") != {
        "default": [],
        "runtime-execution": ["brynja-hash-parallel/runtime-execution", "dep:brynja-crypto-cpu-std", "dep:brynja-crypto-cpu"],
    }:
        fail("std execution must remain explicitly opt-in")
    if std_manifest.get("dependencies") != {
        "brynja-core": {"workspace": True},
        "brynja-hash-parallel": {"workspace": True},
        "brynja-crypto-cpu-std": {"workspace": True, "optional": True, "features": ["runtime-execution"]},
        "brynja-crypto-cpu": {"workspace": True, "optional": True, "features": ["hardened-execution"]},
    }:
        fail("std executor dependency boundary changed")
    std_source = "\n".join(loaded[path] for path in STD_SOURCES)
    for token in (
        "pub struct ParallelHashExecutor", "try_reserve_exact",
        "thread::scope", "thread::Builder::new().spawn_scoped",
        "trait ThreadSpawner", "CancellationToken", "WorkerPanicked",
        "max_leaves", "WorkLimitExceeded", "let slots = leaves.min(workers)",
        "operation_gate: Mutex<()>", "TryLockError::WouldBlock",
        "TryLockError::Poisoned", "fn enter_operation",
        "struct LeafStorage", "clear_owned_region(leaf)", "join_worker(handle)",
        "failure.map_or(Ok(()), Err)",
        "pub fn parallel_hash128_bits", "pub fn parallel_hash256_bits",
        "pub fn parallel_hash_xof128_bits", "pub fn parallel_hash_xof256_bits",
    ):
        require(std_source, token, "native executor")
    std_library = loaded[STD / "src/lib.rs"]
    if std_library.count("let _operation = self.enter_operation()?;") != 8:
        fail("every native executor operation must hold the shared operation permit")
    for token in (
        "all_public_operations_reject_concurrent_use_without_waiting",
        "poisoned_operation_gate_fails_closed",
    ):
        require(std_library, token, "executor operation-permit tests")
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
        "zero_and_exceeded_leaf_budgets_fail_before_output",
    ):
        require(executor_tests, token, "executor acceptance")
    for path, token in (
        (PUBLIC[1], "leaf_crypto_main_scheduled_and_hardened_apis_are_operational"),
        (PUBLIC[3], "external_native_executor_is_operational"),
        (DIFFERENTIAL[2], "for index in range(64)"),
        (SUPPORT[0], "PARALLEL_HASH_IMPLEMENTED: bool = true"),
        (SUPPORT[1], "four ParallelHash identities"),
        (SUPPORT[3], "scripts/parallelhash/check-parallelhash-differential.py"),
        (SUPPORT[4], "run_miri -p brynja-hash-parallel --tests"),
        (SUPPORT[5], "-p brynja-hash-parallel-std"),
        (SUPPORT[6], "cargo kani -p brynja-hash-parallel"),
    ):
        require(loaded[path], token, "ParallelHash evidence closure")
    for command in (
        "python3 scripts/parallelhash/check-parallelhash-execution-differential.py",
        "python3 scripts/parallelhash/check-parallelhash-execution-package.py",
        "cargo test --locked --offline --manifest-path assurance/parallelhash-differential/Cargo.toml --features execution --doc",
        "python3 scripts/parallelhash/check-parallelhash-execution-codegen.py --toolchain 1.90.0",
        "python3 scripts/parallelhash/check-parallelhash-execution-codegen.py --toolchain 1.98.1",
        "cargo clippy --locked --offline --manifest-path assurance/parallelhash-differential/Cargo.toml --all-features --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks",
    ):
        require(loaded[SUPPORT[3]], command, "execution repository gate")
    for command in (
        "run_miri -p brynja-hash-parallel --features hardened-execution --lib execution",
        "run_miri -p brynja-hash-parallel --features hardened-execution --test execution",
        "run_miri -p brynja-hash-parallel --features hardened-execution --test execution_stream",
        "run_miri -p brynja-hash-parallel-std --features runtime-execution --lib execution",
    ):
        require(loaded[SUPPORT[4]], command, "execution Miri gate")
    sanitizer = " ".join(loaded[SUPPORT[5]].replace("\\\n", " ").split())
    for package in ("brynja-hash-parallel", "brynja-hash-parallel-std"):
        require(sanitizer, f"-p {package} --features runtime-execution --tests", "execution ASan gate")
    for path, digest in HASHES.items():
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != digest:
            fail(f"ParallelHash reviewed source changed: {path}")
