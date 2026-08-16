#!/usr/bin/env python3
"""Validate Brynja's v0.23.3 complete SHA-2 CPU boundary."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path


POLICY = Path("security/cpu-acceleration-boundary.toml")
CPU = "brynja-crypto-cpu"
DETECTOR = "brynja-crypto-cpu-std"
SHA2 = "brynja-hash-sha2"
EXPECTED_POLICY_SHA256 = "2e08f2af700717faaf552fbe16a4397bad00450f8bbd9cb9d2024a5cdcef6aa6"
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
    (CPU, "src/lib.rs"): "boundary-only",
    (CPU, "src/sha256.rs"): "safe-session-and-attestation-boundary",
    (CPU, "src/sha256_schedule.rs"): "portable-message-schedule",
    (CPU, "src/sha512.rs"): "static-session-and-kat-boundary",
    (CPU, "src/sha512_schedule.rs"): "portable-message-schedule",
    (CPU, "src/x86_sha.rs"): "implemented-unadmitted-candidate-kernel",
    (CPU, "src/aarch64_sha2.rs"): "implemented-unadmitted-candidate-kernel",
    (CPU, "src/riscv64_zknh.rs"): "implemented-unadmitted-candidate-kernel",
    (DETECTOR, "src/lib.rs"): "boundary-only",
    (DETECTOR, "src/runtime_detection.rs"): "runtime-feature-attestation-boundary",
    (DETECTOR, "src/sha512_runtime.rs"): "scalar-fallback-and-reporting-boundary",
}
BACKENDS = {
    "x86-sha": (
        "X86Sha", "x86_64", "src/x86_sha.rs", ("sha",),
        ("x86_64", "sha-usable-on-current-logical-cpu"),
        "implemented-unadmitted-native-evidence-pending",
    ),
    "x86-sha512-scalar": (
        "ScalarOnlySha512", "x86_64", "absent", (),
        ("x86_64", "no-admitted-single-stream-sha512-kernel"),
        "scalar-only-reviewed",
    ),
    "x86-aes-gcm": (
        "X86AesGcm", "x86_64", "src/x86_aes_gcm.rs", ("aes", "pclmulqdq"),
        ("x86_64", "aes-and-pclmulqdq-usable-on-current-logical-cpu"), "reserved",
    ),
    "x86-avx2": (
        "X86Avx2", "x86_64", "src/x86_avx2.rs", ("avx2",),
        ("x86_64", "osxsave-and-xcr0-ymm-state", "avx2-usable-on-current-logical-cpu"),
        "reserved",
    ),
    "x86-avx512": (
        "X86Avx512", "x86_64", "src/x86_avx512.rs", ("avx512f",),
        ("x86_64", "osxsave-and-xcr0-zmm-state", "avx512f-usable-on-current-logical-cpu"),
        "reserved",
    ),
    "aarch64-sha2": (
        "Aarch64Sha2", "aarch64", "src/aarch64_sha2.rs", ("neon", "sha2"),
        ("aarch64", "neon-and-sha2-usable-on-current-logical-cpu"),
        "implemented-unadmitted-native-evidence-pending",
    ),
    "aarch64-sha512": (
        "Aarch64Sha512", "aarch64", "src/aarch64_sha2.rs", ("neon", "sha3"),
        ("aarch64", "neon-and-sha3-usable-on-current-logical-cpu"),
        "implemented-unadmitted-native-evidence-pending",
    ),
    "aarch64-aes-gcm": (
        "Aarch64AesGcm", "aarch64", "src/aarch64_aes_gcm.rs",
        ("neon", "aes", "pmull"),
        ("aarch64", "neon-aes-and-pmull-usable-on-current-logical-cpu"), "reserved",
    ),
    "riscv-vector": (
        "RiscVVector", "riscv", "src/riscv_vector.rs", ("zvknha",),
        ("riscv64", "ratified-vector-crypto", "vector-state-enabled",
         "zvknha-usable-on-current-hart"),
        "reserved",
    ),
    "riscv-scalar-crypto": (
        "RiscVScalarCrypto", "riscv", "src/riscv64_zknh.rs", ("zknh",),
        ("riscv64", "zknh-usable-on-current-hart"),
        "implemented-unadmitted-native-evidence-pending",
    ),
    "riscv-sha512": (
        "RiscVScalarCrypto", "riscv", "src/riscv64_zknh.rs", ("zknh",),
        ("riscv64", "zknh-usable-on-current-hart"),
        "implemented-unadmitted-native-evidence-pending",
    ),
}
BACKEND_KEYS = {
    "id", "identity", "architecture", "module", "status", "sha256",
    "low_level_allowed", "instructions", "abi_preconditions",
}
SOURCE_KEYS = {"package", "path", "status", "sha256"}


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
        "safe_wrapper", "sources", "backends",
    }, "CPU boundary policy")
    if policy["schema"] != {
        "version": 3,
        "milestone": "0.23.3",
        "status": "complete-sha2-family-candidates-and-scalar-decisions",
    }:
        fail("CPU boundary schema drifted")
    if policy["limits"] != {
        "maximum_source_lines": 500,
        "implemented_backend_count": 5,
        "active_backend_count": 0,
        "approved_cpu_low_level_allowances": 5,
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
            "dependencies": [CPU, SHA2], "default_features": [],
            "publication": "deferred-crates-io", "facade_feature": "none",
        },
    }:
        fail("CPU boundary package contract drifted")
    if policy["graph"].get("scalar_owner") != SHA2:
        fail("CPU scalar owner drifted")
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
    if len(allowances) != 5 or len(allowances) != len(set(allowances)):
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
    if cpu.get("features") != {"default": []} or cpu.get("dependencies"):
        fail("no_std CPU package must retain zero dependencies")
    if detector.get("features") != {"default": []}:
        fail("host detector default feature set drifted")
    if set(detector.get("dependencies", {})) != {CPU, SHA2}:
        fail("host detector dependency boundary drifted")
    if sha2.get("features") != {"default": [], "cpu": ["dep:brynja-crypto-cpu"]}:
        fail("SHA-2 optional CPU feature drifted")
    if set(sha2.get("dependencies", {})) != {"brynja-hash-core", CPU}:
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
        for path in (root / "crates" / name / "src").glob("*.rs")
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
    validate_backends(root, policy)
    if hashlib.sha256(policy_path.read_bytes()).hexdigest() != EXPECTED_POLICY_SHA256:
        fail("CPU security policy changed; reopen boundary review")
