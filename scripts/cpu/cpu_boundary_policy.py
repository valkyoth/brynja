#!/usr/bin/env python3
"""Validate Brynja's v0.24.4 SHA-2 and Keccak CPU boundary."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path
from cpu_boundary_backends import BACKENDS


POLICY = Path("security/cpu-acceleration-boundary.toml")
CPU = "brynja-crypto-cpu"
DETECTOR = "brynja-crypto-cpu-std"
SHA2 = "brynja-hash-sha2"
SHA3 = "brynja-hash-sha3"
EXPECTED_POLICY_SHA256 = "d8f60d8b3ecc6f03511232d541fb339a39497203f36e692ea4c1df1579f6574d"
FORBIDDEN_CONSUMERS = (
    "brynja-crypto",
    "brynja-tls",
    "brynja-tls12",
    "brynja-tls13",
    "brynja-tls13-handshake",
    "brynja-dtls",
    "brynja-quic-tls",
    "brynja-legacy",
)
SOURCE_STATUS = {
    (CPU, "src/keccak_hardened_batch/x86/secret.rs"): "hardened-keccak-batch-opaque-register-boundary",
    (CPU, "src/keccak_hardened_batch/arm/secret.rs"): "hardened-keccak-batch-opaque-register-boundary",
    (CPU, "src/sha512_hardened_batch/x86/secret.rs"): "hardened-sha512-batch-opaque-register-boundary",
    (CPU, "src/sha512_hardened_batch/arm/secret.rs"): "hardened-sha512-batch-opaque-register-boundary",
    (CPU, "src/sha256_hardened_batch/x86/secret.rs"): "hardened-sha256-batch-opaque-register-boundary",
    (CPU, "src/sha256_hardened_batch/arm/secret.rs"): "hardened-sha256-batch-opaque-register-boundary",
    (CPU, "src/x86_avx2_keccak/secret.rs"): "hardened-keccak-opaque-register-boundary",
    (CPU, "src/aarch64_sha3_keccak/secret.rs"): "hardened-keccak-opaque-register-boundary",
    (CPU, "src/x86_sha/secret.rs"): "hardened-sha256-opaque-register-boundary",
    (CPU, "src/aarch64_sha2/secret256.rs"): "hardened-sha256-opaque-register-boundary",
    (CPU, "src/x86_sha512/secret.rs"): "hardened-sha512-opaque-register-boundary",
    (CPU, "src/aarch64_sha2/secret512.rs"): "hardened-sha512-opaque-register-boundary",
    (CPU, "src/x86_sha512/authority.rs"): "dedicated-sha512-private-instruction-permit",
    (CPU, "src/x86_sha512/words.rs"): "dedicated-sha512-checked-word-domains",
    (CPU, "src/x86_sha512.rs"): "dedicated-sha512-emulated-execution-kernel",
    (CPU, "src/static_execution/x86_sha512_tests.rs"): "dedicated-sha512-differential-tests",
    (DETECTOR, "src/sha256_hardened_batch/mod.rs"): "hardened-sha256-batch-hosted-selection",
    (DETECTOR, "src/sha256_hardened_batch/platform.rs"): "hardened-sha256-batch-hosted-import",
    (DETECTOR, "src/sha256_hardened_batch/tests.rs"): "hardened-sha256-batch-hosted-tests",
    (DETECTOR, "src/sha512_hardened_batch/mod.rs"): "hardened-sha512-batch-hosted-selection",
    (DETECTOR, "src/sha512_hardened_batch/platform.rs"): "hardened-sha512-batch-hosted-import",
    (DETECTOR, "src/sha512_hardened_batch/tests.rs"): "hardened-sha512-batch-hosted-tests",
    (DETECTOR, "src/keccak_hardened_batch/mod.rs"): "hardened-keccak-batch-hosted-selection",
    (DETECTOR, "src/keccak_hardened_batch/platform.rs"): "hardened-keccak-batch-hosted-import",
    (DETECTOR, "src/keccak_hardened_batch/tests.rs"): "hardened-keccak-batch-hosted-tests",
    (CPU, "src/keccak_hardened_batch/mod.rs"): "hardened-keccak-batch-authority",
    (CPU, "src/keccak_hardened_batch/scratch.rs"): "hardened-keccak-batch-owned-storage",
    (CPU, "src/keccak_hardened_batch/transfer.rs"): "hardened-keccak-batch-opaque-state-transfer",
    (CPU, "src/keccak_hardened_batch/transfer_tests.rs"): "hardened-keccak-batch-state-transfer-tests",
    (CPU, "src/keccak_hardened_batch/platform.rs"): "hardened-keccak-batch-platform-import",
    (CPU, "src/keccak_hardened_batch/x86.rs"): "hardened-keccak-batch-four-lane-avx2",
    (CPU, "src/keccak_hardened_batch/arm.rs"): "hardened-keccak-batch-two-lane-neon",
    (CPU, "src/keccak_hardened_batch/tests.rs"): "hardened-keccak-batch-lifecycle-tests",
    (CPU, "src/sha512_hardened_batch/mod.rs"): "hardened-sha512-batch-authority",
    (CPU, "src/sha512_hardened_batch/scratch.rs"): "hardened-sha512-batch-owned-storage",
    (CPU, "src/sha512_hardened_batch/transfer.rs"): "hardened-sha512-batch-opaque-state-transfer",
    (CPU, "src/sha512_hardened_batch/transfer_tests.rs"): "hardened-sha512-batch-state-transfer-tests",
    (CPU, "src/sha512_hardened_batch/platform.rs"): "hardened-sha512-batch-platform-import",
    (CPU, "src/sha512_hardened_batch/x86.rs"): "hardened-sha512-batch-four-lane-avx2",
    (CPU, "src/sha512_hardened_batch/arm.rs"): "hardened-sha512-batch-two-lane-neon",
    (CPU, "src/sha512_hardened_batch/tests.rs"): "hardened-sha512-batch-lifecycle-tests",
    (CPU, "src/sha256_hardened_batch/mod.rs"): "hardened-sha256-batch-authority",
    (CPU, "src/sha256_hardened_batch/scratch.rs"): "hardened-sha256-batch-owned-storage",
    (CPU, "src/sha256_hardened_batch/transfer.rs"): "hardened-sha256-batch-opaque-state-transfer",
    (CPU, "src/sha256_hardened_batch/transfer_tests.rs"): "hardened-sha256-batch-state-transfer-tests",
    (CPU, "src/sha256_hardened_batch/platform.rs"): "hardened-sha256-batch-platform-import",
    (CPU, "src/sha256_hardened_batch/x86.rs"): "hardened-sha256-eight-lane-avx2",
    (CPU, "src/sha256_hardened_batch/arm.rs"): "hardened-sha256-four-lane-neon",
    (CPU, "src/sha256_hardened_batch/tests.rs"): "hardened-sha256-batch-lifecycle-tests",
    (CPU, "src/keccak_batch/mod.rs"): "ordinary-keccak-batch-authority",
    (CPU, "src/keccak_batch/platform.rs"): "ordinary-keccak-batch-platform-import",
    (CPU, "src/keccak_batch/x86.rs"): "ordinary-keccak-four-state-avx2",
    (CPU, "src/keccak_batch/arm.rs"): "ordinary-keccak-two-state-neon",
    (CPU, "src/keccak_batch/tests.rs"): "ordinary-keccak-batch-authority-tests",
    (DETECTOR, "src/keccak_batch/mod.rs"): "ordinary-keccak-batch-hosted-selection",
    (DETECTOR, "src/keccak_batch/platform.rs"): "ordinary-keccak-batch-hosted-import",
    (DETECTOR, "src/keccak_batch/tests.rs"): "ordinary-keccak-batch-hosted-selection-tests",
    (CPU, "src/sha512_batch/mod.rs"): "ordinary-sha512-batch-authority",
    (CPU, "src/sha512_batch/platform.rs"): "ordinary-sha512-batch-platform-import",
    (CPU, "src/sha512_batch/x86.rs"): "ordinary-sha512-four-lane-avx2",
    (CPU, "src/sha512_batch/arm.rs"): "ordinary-sha512-two-lane-neon",
    (CPU, "src/sha512_batch/tests.rs"): "ordinary-sha512-batch-authority-tests",
    (DETECTOR, "src/sha512_batch/mod.rs"): "ordinary-sha512-batch-hosted-selection",
    (DETECTOR, "src/sha512_batch/platform.rs"): "ordinary-sha512-batch-hosted-import",
    (DETECTOR, "src/sha512_batch/tests.rs"): "ordinary-sha512-batch-hosted-selection-tests",
    (CPU, "src/sha256_batch/mod.rs"): "ordinary-sha256-batch-authority",
    (CPU, "src/sha256_batch/platform.rs"): "ordinary-sha256-batch-platform-import",
    (CPU, "src/sha256_batch/x86.rs"): "ordinary-sha256-eight-lane-avx2",
    (CPU, "src/sha256_batch/arm.rs"): "ordinary-sha256-four-lane-neon",
    (CPU, "src/sha256_batch/tests.rs"): "ordinary-sha256-batch-authority-tests",
    (DETECTOR, "src/sha256_batch/mod.rs"): "ordinary-sha256-batch-hosted-selection",
    (DETECTOR, "src/sha256_batch/platform.rs"): "ordinary-sha256-batch-hosted-import",
    (DETECTOR, "src/sha256_batch/tests.rs"): "ordinary-sha256-batch-hosted-selection-tests",
    (CPU, "src/hardened_execution/keccak.rs"): "hardened-keccak-authority-and-cleanup",
    (CPU, "src/hardened_execution/keccak_scratch.rs"): "hardened-keccak-owned-scratch",
    (CPU, "src/hardened_execution/keccak/tests.rs"): "hardened-keccak-lifecycle-tests",
    (CPU, "src/hardened_execution/mod.rs"): "hardened-authority-and-operation-cleanup",
    (CPU, "src/hardened_execution/scratch.rs"): "hardened-owner-backed-kernel-scratch",
    (CPU, "src/hardened_execution/tests.rs"): "hardened-kernel-and-lifecycle-tests",
    (CPU, "src/runtime_execution/mod.rs"): "ordinary-runtime-authority",
    (CPU, "src/runtime_execution/operations.rs"): "runtime-kat-and-operation-routing",
    (CPU, "src/runtime_execution/tests.rs"): "runtime-authority-tests",
    (DETECTOR, "src/execution/mod.rs"): "hosted-execution-selection",
    (DETECTOR, "src/execution/features.rs"): "complete-hosted-feature-bundles",
    (DETECTOR, "src/execution/platform.rs"): "system-feature-proof-boundary",
    (DETECTOR, "src/execution/tests.rs"): "hosted-execution-tests",
    (CPU, "src/static_execution/mod.rs"): "ordinary-static-authority",
    (CPU, "src/static_execution/kernel.rs"): "complete-static-feature-bundles",
    (CPU, "src/static_execution/public_data.rs"): "explicit-public-data-classification",
    (CPU, "src/static_execution/operations.rs"): "static-kat-and-operation-routing",
    (CPU, "src/static_execution/tests.rs"): "static-authority-tests",
    (CPU, "src/lib.rs"): "boundary-only",
    (CPU, "src/sha256.rs"): "safe-session-and-attestation-boundary",
    (CPU, "src/sha256_schedule.rs"): "portable-message-schedule",
    (CPU, "src/sha512.rs"): "static-session-and-kat-boundary",
    (CPU, "src/sha512_schedule.rs"): "portable-message-schedule",
    (CPU, "src/keccak.rs"): "safe-session-and-attestation-boundary",
    (CPU, "src/keccak_constants.rs"): "portable-keccak-constants",
    (CPU, "src/x86_sha.rs"): "implemented-unadmitted-candidate-kernel",
    (CPU, "src/aarch64_sha2.rs"): "implemented-unadmitted-candidate-kernel",
    (CPU, "src/riscv64_zknh.rs"): "implemented-unadmitted-candidate-kernel",
    (CPU, "src/x86_avx2_keccak.rs"): "implemented-unadmitted-candidate-kernel",
    (CPU, "src/aarch64_sha3_keccak.rs"): "implemented-unadmitted-candidate-kernel",
    (DETECTOR, "src/lib.rs"): "boundary-only",
    (DETECTOR, "src/runtime_detection.rs"): "runtime-feature-attestation-boundary",
    (DETECTOR, "src/sha512_runtime.rs"): "scalar-fallback-and-reporting-boundary",
    (DETECTOR, "src/sponge.rs"): "opt-in-ordinary-sponge-adapter",
    (DETECTOR, "src/sponge/tests.rs"): "ordinary-sponge-adapter-tests",
    (DETECTOR, "src/protected_memory/mod.rs"): "opt-in-protected-storage-resource",
    (DETECTOR, "src/protected_memory/unsupported.rs"): "protected-resource-unsupported-rejection",
    (DETECTOR, "src/protected_memory/tests.rs"): "protected-resource-contract-tests",
    (DETECTOR, "src/protected_memory/platform.rs"): "linux-protected-mapping-owner",
    (DETECTOR, "src/protected_memory/stack.rs"): "synchronous-protected-stack-owner",
    (DETECTOR, "src/protected_memory/platform/sys.rs"): "linux-memory-protection-ffi",
    (DETECTOR, "src/protected_memory/platform/tests.rs"): "linux-mapping-lifecycle-tests",
    (DETECTOR, "src/protected_memory/platform/thread.rs"): "linux-scoped-pthread-owner",
    (DETECTOR, "src/protected_memory/platform/thread/tests.rs"): "linux-protected-stack-lifecycle-tests",
    (DETECTOR, "src/strict_sha2/mod.rs"): "protected-scalar-sha2-session-development",
    (DETECTOR, "src/strict_sha2/types.rs"): "protected-sha2-public-identity-and-bounds",
    (DETECTOR, "src/strict_sha2/worker.rs"): "protected-sha2-scoped-worker",
    (DETECTOR, "src/strict_sha2/tests.rs"): "protected-sha2-integration-tests",
}
BACKEND_KEYS = {
    "id", "identity", "architecture", "module", "status", "sha256",
    "low_level_allowed", "instructions", "abi_preconditions",
}
SOURCE_KEYS = {"package", "path", "status", "sha256"}
EVIDENCE_KEYS = {"path", "status", "sha256"}
EVIDENCE_STATUS = {
    "assurance/sha3-cpu-candidate/Cargo.toml": "isolated-candidate-fixture-manifest",
    "assurance/sha3-cpu-candidate/Cargo.lock": "isolated-candidate-fixture-lock",
    "assurance/sha3-cpu-candidate/src/lib.rs": "six-identity-scalar-differential",
    "assurance/sha3-cpu-candidate/src/main.rs": "candidate-fixture-entrypoint",
    "scripts/sha3/check-sha3-cpu-codegen.sh": "compiler-endpoint-instruction-evidence",
    "scripts/sha3/check-sha3-cpu-qemu.sh": "supplemental-aarch64-execution-evidence",
}


class CpuBoundaryPolicyError(RuntimeError):
    """The reviewed CPU boundary differs from policy."""
def fail(message: str) -> None:
    raise CpuBoundaryPolicyError(message)
def read_toml(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read {path}: {error}")
def exact_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} fields drifted")
def manifest(root: Path, name: str) -> dict:
    return read_toml(root / "crates" / name / "Cargo.toml")
def validate_policy_shape(policy: dict) -> None:
    exact_keys(policy, {
        "schema", "limits", "packages", "graph", "fips", "low_level_boundary",
        "safe_wrapper", "evidence", "sources", "backends",
    }, "CPU boundary policy")
    if policy["schema"] != {
        "version": 4,
        "milestone": "0.24.4",
        "status": "sha2-and-keccak-candidates-with-scalar-decisions",
    }:
        fail("CPU boundary schema drifted")
    if policy["limits"] != {
        "maximum_source_lines": 500,
        "implemented_backend_count": 7,
        "active_backend_count": 0,
        "approved_cpu_low_level_allowances": 8,
    }:
        fail("CPU boundary limits drifted")
    if policy["packages"] != {
        "kernel": {
            "name": CPU, "version": "0.1.1", "runtime": "no_std",
            "dependencies": [], "default_features": [],
            "publication": "deferred-crates-io", "facade_feature": "none",
        },
        "detector": {
            "name": DETECTOR, "version": "0.1.1", "runtime": "std",
            "dependencies": [CPU, SHA2, SHA3, "brynja-core"], "default_features": [],
            "publication": "deferred-crates-io", "facade_feature": "none",
        },
    }:
        fail("CPU boundary package contract drifted")
    if policy["graph"].get("scalar_owners") != [SHA2, SHA3]:
        fail("CPU scalar owners drifted")
    if policy["graph"].get("forbidden_consumers") != list(FORBIDDEN_CONSUMERS):
        fail("CPU forbidden-consumer inventory drifted")
    for key in (
        "third_party_detection_crates", "build_time_source_inclusion",
        "implicit_std", "os_entropy_and_platform_services",
    ):
        if policy["graph"].get(key) != "forbidden":
            fail(f"CPU graph prohibition drifted: {key}")
    if policy["fips"] != {
        "future_module": "brynja-fips-module",
        "ordinary_facade_claim": "forbidden",
        "detector_adapter": "excluded",
        "feature_unification_changes_artifact": "forbidden",
        "kernel_inclusion": "exact-reviewed-symbols-only",
        "dispatch_table": "artifact-owned",
        "operational_environment": "artifact-owned",
    }:
        fail("FIPS CPU-package boundary drifted")
    allowances = policy["low_level_boundary"].get("current_cpu_allowances", [])
    if len(allowances) != 8 or len(allowances) != len(set(allowances)):
        fail("CPU low-level allowance inventory drifted")
    invariants = policy["safe_wrapper"].get("invariants", [])
    if len(invariants) != 15 or len(invariants) != len(set(invariants)):
        fail("safe wrapper invariant inventory drifted")
def validate_packages(root: Path) -> None:
    workspace = read_toml(root / "Cargo.toml")["workspace"]["dependencies"]
    expected_pins = {CPU: "=0.1.1", DETECTOR: "=0.1.1", SHA2: "=0.1.0"}
    for name, version in expected_pins.items():
        if workspace.get(name) != {"path": f"crates/{name}", "version": version}:
            fail(f"workspace dependency pin drifted: {name}")
    cpu = manifest(root, CPU)
    detector = manifest(root, DETECTOR)
    sha2 = manifest(root, SHA2)
    if cpu.get("features") != {"default": [], "sha256-hardened-batch": ["dep:brynja-core"], "sha512-hardened-batch": ["dep:brynja-core"], "keccak-hardened-batch": ["dep:brynja-core"], "keccak-batch": ["static-execution"], "static-execution": [], "runtime-execution": ["static-execution"],
            "hardened-execution": ["static-execution", "dep:brynja-core"], "sha256-batch": ["static-execution"], "sha512-batch": ["static-execution"]} or cpu.get("dependencies") != {
                "brynja-core": {"workspace": True, "optional": True}}:
        fail("no_std CPU package permits only its opt-in first-party clearing dependency")
    if detector.get("features") != {"default": [],
            "protected-memory": ["dep:brynja-core"],
            "strict-sha2": ["protected-memory", "brynja-hash-sha2/general-sha512-t"],
            "sha256-hardened-batch": ["brynja-crypto-cpu/sha256-hardened-batch", "brynja-hash-sha2/hardened-batch-execution"],
            "sha512-hardened-batch": ["brynja-crypto-cpu/sha512-hardened-batch", "brynja-hash-sha2/hardened-batch512-execution"],
            "keccak-hardened-batch": ["brynja-crypto-cpu/keccak-hardened-batch", "dep:brynja-hash-sha3", "brynja-hash-sha3/hardened-batch-execution"],
            "keccak-batch": ["brynja-crypto-cpu/keccak-batch", "dep:brynja-hash-sha3", "brynja-hash-sha3/batch-execution"], "runtime-execution": ["brynja-crypto-cpu/runtime-execution"],
            "sponge-execution": ["runtime-execution", "dep:brynja-hash-sha3", "brynja-hash-sha3/runtime-execution"], "sha256-batch": ["brynja-crypto-cpu/sha256-batch", "brynja-hash-sha2/batch-execution"], "sha512-batch": ["brynja-crypto-cpu/sha512-batch", "brynja-hash-sha2/batch512-execution"]}:
        fail("host detector default feature set drifted")
    if set(detector.get("dependencies", {})) != {CPU, SHA2, SHA3, "brynja-core"} or detector['dependencies'][SHA3] != {'workspace': True, 'optional': True} or detector['dependencies']['brynja-core'] != {'workspace': True, 'optional': True}:
        fail("host detector dependency boundary drifted")
    if sha2.get("features") != {
        "default": [], "cpu": ["dep:brynja-crypto-cpu"], "general-sha512-t": [],
        "batch-execution": ["cpu", "brynja-crypto-cpu/sha256-batch"],
        "hardened-batch-execution": ["cpu", "brynja-crypto-cpu/sha256-hardened-batch"],
        "hardened-batch512-execution": ["cpu", "general-sha512-t", "brynja-crypto-cpu/sha512-hardened-batch"],
        "batch512-execution": ["cpu", "general-sha512-t", "brynja-crypto-cpu/sha512-batch"],
        "static-execution": ["cpu", "brynja-crypto-cpu/static-execution"],
        "runtime-execution": ["static-execution", "brynja-crypto-cpu/runtime-execution"],
        "hardened-execution": ["static-execution", "brynja-crypto-cpu/hardened-execution"],
    }:
        fail("SHA-2 optional CPU feature drifted")
    if set(sha2.get("dependencies", {})) != {"brynja-core", "brynja-hash-core", CPU}:
        fail("SHA-2 CPU dependency boundary drifted")
    packages = read_toml(root / "package-policy.toml")["packages"]
    if packages[SHA2]["optional"] != {"cpu": CPU}:
        fail("SHA-2 package classification lost optional CPU isolation")
    if packages[DETECTOR]["required"] != [CPU, SHA2]:
        fail("detector package classification drifted")
    facade = manifest(root, "brynja")
    if CPU in facade.get("dependencies", {}) or DETECTOR in facade.get("dependencies", {}):
        fail("CPU packages entered the ordinary facade")
    for consumer in FORBIDDEN_CONSUMERS:
        dependencies = manifest(root, consumer).get("dependencies", {})
        if CPU in dependencies or DETECTOR in dependencies:
            fail(f"forbidden CPU package consumer: {consumer}")
    for name in (CPU, DETECTOR):
        package = manifest(root, name)["package"]
        if "build" in package or "links" in package or (root / "crates" / name / "build.rs").exists():
            fail(f"CPU boundary introduced build or native linking: {name}")
def validate_sources(root: Path, policy: dict) -> None:
    records = policy["sources"]
    if len(records) != len(SOURCE_STATUS):
        fail("CPU source inventory is incomplete")
    seen = set()
    for record in records:
        exact_keys(record, SOURCE_KEYS, "CPU source")
        key = (record["package"], record["path"])
        if key in seen or SOURCE_STATUS.get(key) != record["status"]:
            fail("CPU source inventory or status drifted")
        seen.add(key)
        path = root / "crates" / key[0] / key[1]
        if not path.is_file() or path.is_symlink():
            fail(f"CPU source must be a regular file: {key}")
        if len(path.read_text(encoding="utf-8").splitlines()) > policy["limits"]["maximum_source_lines"]:
            fail(f"CPU source exceeds 500 lines: {key}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
            fail(f"CPU source changed; reopen security review: {key}")
    if seen != set(SOURCE_STATUS):
        fail("CPU source inventory is incomplete")
    actual = {
        (name, str(path.relative_to(root / "crates" / name)))
        for name in (CPU, DETECTOR)
        for path in (root / "crates" / name / "src").rglob("*.rs")
    }
    if actual != set(SOURCE_STATUS):
        fail("unreviewed source entered CPU packages")
    text = {key: (root / "crates" / key[0] / key[1]).read_text(encoding="utf-8") for key in SOURCE_STATUS}
    if "#![no_std]" not in text[(CPU, "src/lib.rs")]:
        fail("CPU kernel package lost no_std")
    if "#![no_std]" in text[(DETECTOR, "src/lib.rs")]:
        fail("std detector still claims no_std")
    x86 = text[(CPU, "src/x86_sha.rs")]
    for token in ('#[target_feature(enable = "sha")]', "_mm_sha256rnds2_epu32", "// SAFETY:"):
        if token not in x86:
            fail(f"x86 SHA kernel drifted: {token}")
    arm = text[(CPU, "src/aarch64_sha2.rs")]
    for token in (
        '#[target_feature(enable = "sha2")]', '#[target_feature(enable = "sha3")]',
        "vsha256hq_u32", "vsha256h2q_u32", "vsha512hq_u64", "vsha512h2q_u64",
        "// SAFETY:",
    ):
        if token not in arm:
            fail(f"AArch64 SHA2 kernel drifted: {token}")
    riscv = text[(CPU, "src/riscv64_zknh.rs")]
    for token in (
        '#[target_feature(enable = "zknh")]', "sha256sig0", "sha256sig1",
        "sha256sum0", "sha256sum1", "sha512sum0", "sha512sum1",
        "options(pure, nomem, nostack)", "// SAFETY:",
    ):
        if token not in riscv:
            fail(f"RISC-V Zknh kernel drifted: {token}")
    if re.search(r'extern\s+"C"|\bglobal_asm\s*!', riscv):
        fail("RISC-V Zknh kernel introduced external assembly or native linkage")
    x86_keccak = text[(CPU, "src/x86_avx2_keccak.rs")]
    for token in ('#[target_feature(enable = "avx2")]', "_mm256_andnot_si256", "// SAFETY:"):
        if token not in x86_keccak:
            fail(f"x86 AVX2 Keccak kernel drifted: {token}")
    arm_keccak = text[(CPU, "src/aarch64_sha3_keccak.rs")]
    for token in (
        '#[target_feature(enable = "sha3")]', "veor3q_u64", "vrax1q_u64",
        "vbcaxq_u64", "// SAFETY:",
    ):
        if token not in arm_keccak:
            fail(f"AArch64 SHA3 Keccak kernel drifted: {token}")
    for kernel in (x86_keccak, arm_keccak):
        if re.search(r'extern\s+"C"|\basm\s*!|\bglobal_asm\s*!', kernel):
            fail("Keccak kernel introduced native linkage or assembly")
    detector = text[(DETECTOR, "src/runtime_detection.rs")]
    for token in (
        'is_x86_feature_detected!("sha")', 'is_aarch64_feature_detected!("sha2")',
        'is_aarch64_feature_detected!("sha3")', "// SAFETY:",
    ):
        if token not in detector:
            fail(f"runtime detector drifted: {token}")
    if "is_riscv_feature_detected" in detector or "RiscVScalarCrypto" in detector:
        fail("RISC-V automatic runtime activation is not authorized")
    session = text[(CPU, "src/sha256.rs")]
    for token in ('target_arch = "riscv64"', 'target_feature = "zknh"'):
        if token not in session:
            fail(f"RISC-V static selection lost exact compiler proof: {token}")
    schedule = text[(CPU, "src/sha256_schedule.rs")]
    schedule += text[(CPU, "src/sha512_schedule.rs")]
    if re.search(r"\b(?:unsafe|core::arch|std::|alloc::)\b", schedule):
        fail("portable CPU message schedule crossed a low-level boundary")
    sha512 = text[(CPU, "src/sha512.rs")]
    for token in (
        "pub enum Sha512Backend", "pub struct Sha512BackendSession",
        "target_feature = \"sha3\"", "target_feature = \"zknh\"",
        "Sha512BackendHealth::Quarantined",
    ):
        if token not in sha512:
            fail(f"SHA-512 session boundary drifted: {token}")
    keccak = text[(CPU, "src/keccak.rs")]
    for token in (
        "pub enum KeccakBackend", "pub struct KeccakBackendSession",
        'target_feature = "avx2"', 'target_feature = "sha3"',
        "KeccakBackendHealth::Quarantined", "pub const fn is_admitted",
    ):
        if token not in keccak:
            fail(f"Keccak session boundary drifted: {token}")


def validate_evidence(root: Path, policy: dict) -> None:
    records = policy["evidence"]
    if len(records) != len(EVIDENCE_STATUS):
        fail("CPU evidence-program inventory is incomplete")
    seen = set()
    for record in records:
        exact_keys(record, EVIDENCE_KEYS, "CPU evidence program")
        path = record["path"]
        if path in seen or EVIDENCE_STATUS.get(path) != record["status"]:
            fail("CPU evidence-program inventory or status drifted")
        seen.add(path)
        source = root / path
        if not source.is_file() or source.is_symlink():
            fail(f"CPU evidence input must be a regular file: {path}")
        if len(source.read_text(encoding="utf-8").splitlines()) > 500:
            fail(f"CPU evidence input exceeds 500 lines: {path}")
        if hashlib.sha256(source.read_bytes()).hexdigest() != record["sha256"]:
            fail(f"CPU evidence input changed; reopen review: {path}")
    if seen != set(EVIDENCE_STATUS):
        fail("CPU evidence-program inventory is incomplete")
    checks = (root / "scripts/checks.sh").read_text(encoding="utf-8")
    command = "scripts/sha3/check-sha3-cpu-codegen.sh"
    if checks.count(command) != 1:
        fail("ordinary checks lost SHA-3 CPU codegen evidence")
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for target in ("aarch64-unknown-linux-gnu", "riscv64gc-unknown-linux-gnu"):
        if workflow.count(target) < 2:
            fail(f"CI lost CPU compiler-target installation: {target}")


def validate_backends(root: Path, policy: dict) -> None:
    records = policy["backends"]
    if len(records) != len(BACKENDS):
        fail("CPU backend inventory is incomplete")
    seen = set()
    for record in records:
        exact_keys(record, BACKEND_KEYS, "CPU backend")
        identifier = record["id"]
        expected = BACKENDS.get(identifier)
        if identifier in seen or expected is None:
            fail("CPU backend identity drifted")
        seen.add(identifier)
        identity, architecture, module, instructions, preconditions, status = expected
        if (
            record["identity"] != identity or record["architecture"] != architecture
            or record["module"] != module or tuple(record["instructions"]) != instructions
            or tuple(record["abi_preconditions"]) != preconditions or record["status"] != status
        ):
            fail(f"CPU backend contract drifted: {identifier}")
        path = root / "crates" / CPU / module
        if status == "reserved":
            if record["sha256"] != "absent" or record["low_level_allowed"] is not False or path.exists():
                fail(f"reserved backend gained implementation authority: {identifier}")
        elif status == "scalar-only-reviewed":
            if record["sha256"] != "absent" or record["low_level_allowed"] is not False:
                fail(f"scalar-only decision gained implementation authority: {identifier}")
        else:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if record["sha256"] != digest or record["low_level_allowed"] is not True:
                fail(f"candidate backend source binding drifted: {identifier}")
    if seen != set(BACKENDS):
        fail("CPU backend inventory is incomplete")


def validate(root: Path) -> None:
    policy_path = root / POLICY
    policy = read_toml(policy_path)
    validate_policy_shape(policy)
    validate_packages(root)
    validate_sources(root, policy)
    validate_evidence(root, policy)
    validate_backends(root, policy)
    if hashlib.sha256(policy_path.read_bytes()).hexdigest() != EXPECTED_POLICY_SHA256:
        fail("CPU security policy changed; reopen boundary review")
