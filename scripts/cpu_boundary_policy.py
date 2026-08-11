#!/usr/bin/env python3
"""Validate the inert v0.13.2 CPU-package and future admission boundary."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path


POLICY = Path("security/cpu-acceleration-boundary.toml")
CPU = "brynja-crypto-cpu"
DETECTOR = "brynja-crypto-cpu-std"
EXPECTED_POLICY_SHA256 = "dfebd0f108f7fe5f543969022f15c0ae1c4bedf7767d30008213ada64694811e"
EXPECTED_SOURCE_SHA256 = {
    (CPU, "src/lib.rs"): "614731a47da9364a16d62b71335b5cbeffb7554b117d4c2c8661fd5b2b2ec438",
    (DETECTOR, "src/lib.rs"): "db734d07aca12e88b560d732d977d97f9e86e438ef913f6b3d5d19c733a9d7a2",
}
NO_STD_ATTRIBUTE = re.compile(r"(?m)^#!\[no_std\]$")
FALSE_STATUS = {
    (CPU, "src/lib.rs"): re.compile(r"(?m)^pub const IMPLEMENTED: bool = false;$"),
    (DETECTOR, "src/lib.rs"): re.compile(
        r"(?m)^pub const RUNTIME_DETECTION_IMPLEMENTED: bool = false;$"
    ),
}
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
LOW_LEVEL = re.compile(
    r"\b(?:unsafe|unsafe_code|extern|asm|global_asm|llvm_asm|naked_asm|include|path)\b"
)
BACKENDS = {
    "x86-sha": (
        "X86Sha",
        "x86_64",
        "src/x86_sha.rs",
        ("sha",),
        ("x86_64", "sha-usable-on-current-logical-cpu"),
    ),
    "x86-aes-gcm": (
        "X86AesGcm",
        "x86_64",
        "src/x86_aes_gcm.rs",
        ("aes", "pclmulqdq"),
        ("x86_64", "aes-and-pclmulqdq-usable-on-current-logical-cpu"),
    ),
    "x86-avx2": (
        "X86Avx2",
        "x86_64",
        "src/x86_avx2.rs",
        ("avx2",),
        ("x86_64", "osxsave-and-xcr0-ymm-state", "avx2-usable-on-current-logical-cpu"),
    ),
    "x86-avx512": (
        "X86Avx512",
        "x86_64",
        "src/x86_avx512.rs",
        ("avx512f",),
        ("x86_64", "osxsave-and-xcr0-zmm-state", "avx512f-usable-on-current-logical-cpu"),
    ),
    "aarch64-sha2": (
        "Aarch64Sha2",
        "aarch64",
        "src/aarch64_sha2.rs",
        ("neon", "sha2"),
        ("aarch64", "neon-and-sha2-usable-on-current-logical-cpu"),
    ),
    "aarch64-aes-gcm": (
        "Aarch64AesGcm",
        "aarch64",
        "src/aarch64_aes_gcm.rs",
        ("neon", "aes", "pmull"),
        ("aarch64", "neon-aes-and-pmull-usable-on-current-logical-cpu"),
    ),
    "riscv-vector": (
        "RiscVVector",
        "riscv",
        "src/riscv_vector.rs",
        ("v",),
        ("ratified-vector-isa", "vector-state-enabled", "v-usable-on-current-hart"),
    ),
    "riscv-scalar-crypto": (
        "RiscVScalarCrypto",
        "riscv",
        "src/riscv_scalar_crypto.rs",
        ("ratified-scalar-crypto-subset",),
        ("matching-riscv-width", "exact-scalar-crypto-subset-usable-on-current-hart"),
    ),
}
AMENDMENT_REQUIREMENTS = (
    "primitive-and-operation",
    "source-symbol-and-sha256",
    "compiler-and-feature-bundle",
    "instruction-preconditions",
    "abi-and-vector-state-preconditions",
    "safe-wrapper-invariants",
    "register-and-spill-residuals",
    "scalar-reference",
    "known-answer-test",
    "quarantine-path",
    "native-hardware-evidence",
    "side-channel-evidence",
    "performance-evidence",
    "fips-disposition",
    "independent-review",
)
FORBIDDEN_MECHANISMS = (
    "foreign-abi",
    "external-assembly",
    "native-object",
    "build-script",
    "generated-source-inclusion",
    "global-registry",
)
SAFE_WRAPPER_INVARIANTS = (
    "exact-backend-identity",
    "complete-feature-bundle",
    "operating-state-preconditions",
    "exact-session-and-instance",
    "successful-direct-kat",
    "healthy-current-generation",
    "exact-operation-authority",
    "migration-exclusion-through-call",
    "post-callback-logical-revalidation",
    "guarded-direct-kernel-call",
    "bounded-caller-owned-buffers",
    "scalar-differential-equivalence",
    "secret-free-failure",
)
SOURCE_KEYS = {"package", "path", "status", "sha256"}
BACKEND_KEYS = {
    "id",
    "identity",
    "architecture",
    "module",
    "status",
    "sha256",
    "low_level_allowed",
    "instructions",
    "abi_preconditions",
}


class CpuBoundaryPolicyError(RuntimeError):
    """The reserved CPU boundary or future-admission contract drifted."""


def fail(message: str) -> None:
    raise CpuBoundaryPolicyError(message)


def exact_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} fields drifted")


def read_toml(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read {path}: {error}")


def package_manifest(root: Path, name: str) -> dict:
    return read_toml(root / "crates" / name / "Cargo.toml")


def validate_package_policy(root: Path) -> None:
    packages = read_toml(root / "package-policy.toml").get("packages", {})
    expected = {
        CPU: {
            "class": "cpu-backend",
            "publish": "crates-io",
            "required": [],
            "optional": {},
        },
        DETECTOR: {
            "class": "host-adapter",
            "publish": "crates-io",
            "required": [CPU],
            "optional": {},
        },
    }
    for name, entry in expected.items():
        if packages.get(name) != entry:
            fail(f"package classification drifted: {name}")
    facade = packages.get("brynja", {})
    if CPU in facade.get("required", []) or CPU in facade.get("optional", {}).values():
        fail("ordinary facade must remain independent of CPU packages")


def validate_manifests(root: Path) -> None:
    workspace = read_toml(root / "Cargo.toml")
    workspace_dependencies = workspace.get("workspace", {}).get("dependencies", {})
    for name in (CPU, DETECTOR):
        expected = {"path": f"crates/{name}", "version": "=0.1.0"}
        if workspace_dependencies.get(name) != expected:
            fail(f"workspace dependency pin drifted: {name}")

    cpu = package_manifest(root, CPU)
    detector = package_manifest(root, DETECTOR)
    facade = package_manifest(root, "brynja")
    if cpu.get("features") != {"default": []} or cpu.get("dependencies"):
        fail("no_std CPU package must have empty features and zero dependencies")
    if detector.get("features") != {"default": []}:
        fail("host detector default feature set drifted")
    if detector.get("dependencies") != {CPU: {"workspace": True}}:
        fail("host detector may depend only on the no_std CPU package")
    facade_dependencies = facade.get("dependencies", {})
    if (
        CPU in facade_dependencies
        or DETECTOR in facade_dependencies
        or CPU in facade.get("features", {})
        or DETECTOR in facade.get("features", {})
    ):
        fail("CPU package entered the ordinary facade")
    if facade.get("features", {}).get("default") != []:
        fail("facade default feature set activated CPU code")

    allowed_owners = {DETECTOR: {CPU}}
    for manifest_path in sorted((root / "crates").glob("*/Cargo.toml")):
        manifest = read_toml(manifest_path)
        owner = manifest.get("package", {}).get("name")
        dependencies = set(manifest.get("dependencies", {}))
        cpu_dependencies = dependencies.intersection({CPU, DETECTOR})
        if cpu_dependencies != allowed_owners.get(owner, set()):
            fail(f"CPU package dependency direction drifted: {owner}")
        package = manifest.get("package", {})
        if "build" in package or "links" in package:
            fail(f"CPU boundary package introduced build or native linking: {owner}")
    for consumer in FORBIDDEN_CONSUMERS:
        dependencies = package_manifest(root, consumer).get("dependencies", {})
        if CPU in dependencies or DETECTOR in dependencies:
            fail(f"forbidden CPU package consumer: {consumer}")


def validate_sources(root: Path, policy: dict) -> None:
    maximum = policy["limits"]["maximum_source_lines"]
    records = policy.get("sources", [])
    if len(records) != 2:
        fail("boundary source inventory must contain exactly two files")
    seen: set[tuple[str, str]] = set()
    for record in records:
        exact_keys(record, SOURCE_KEYS, "boundary source")
        key = (record["package"], record["path"])
        if key in seen or key not in {(CPU, "src/lib.rs"), (DETECTOR, "src/lib.rs")}:
            fail("boundary source inventory drifted")
        seen.add(key)
        if record["status"] != "boundary-only":
            fail("boundary source claimed implementation")
        path = root / "crates" / record["package"] / record["path"]
        if not path.is_file() or path.is_symlink():
            fail(f"boundary source is not a regular file: {path}")
        text = path.read_text(encoding="utf-8")
        if len(text.splitlines()) > maximum:
            fail(f"boundary source exceeds {maximum} lines")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        expected = EXPECTED_SOURCE_SHA256[key]
        if record["sha256"] != expected or digest != expected:
            fail(f"inert boundary source changed; reopen security review: {key}")
        if len(NO_STD_ATTRIBUTE.findall(text)) != 1:
            fail(f"real no_std attribute missing: {key}")
        if FALSE_STATUS[key].search(text) is None:
            fail(f"exact false implementation declaration missing: {key}")
        if LOW_LEVEL.search(text):
            fail(f"boundary source gained a low-level token: {key}")
        rust_sources = sorted(path.parent.rglob("*.rs"))
        if rust_sources != [path]:
            fail(f"unadmitted source entered reserved package: {record['package']}")
        if (path.parents[1] / "build.rs").exists():
            fail(f"build-time source generation entered: {record['package']}")


def validate_backends(root: Path, policy: dict) -> None:
    records = policy.get("backends", [])
    if len(records) != len(BACKENDS):
        fail("reserved backend inventory is incomplete")
    seen: set[str] = set()
    for record in records:
        exact_keys(record, BACKEND_KEYS, "reserved backend")
        identifier = record["id"]
        if identifier in seen or identifier not in BACKENDS:
            fail("reserved backend identity drifted")
        seen.add(identifier)
        identity, architecture, module, instructions, abi_preconditions = BACKENDS[identifier]
        if (
            record["identity"] != identity
            or record["architecture"] != architecture
            or record["module"] != module
            or tuple(record["instructions"]) != instructions
            or tuple(record["abi_preconditions"]) != abi_preconditions
        ):
            fail(f"reserved backend contract drifted: {identifier}")
        if (
            record["status"] != "reserved"
            or record["sha256"] != "absent"
            or record["low_level_allowed"] is not False
        ):
            fail(f"reserved backend gained implementation authority: {identifier}")
        if (root / "crates" / CPU / record["module"]).exists():
            fail(f"reserved backend module exists without admission: {identifier}")


def validate_policy_shape(policy: dict) -> None:
    exact_keys(
        policy,
        {
            "schema",
            "limits",
            "packages",
            "graph",
            "fips",
            "low_level_boundary",
            "safe_wrapper",
            "sources",
            "backends",
        },
        "CPU boundary policy",
    )
    if policy["schema"] != {
        "version": 1,
        "milestone": "0.13.2",
        "status": "reserved-no-implementation",
    }:
        fail("CPU boundary schema drifted")
    if policy["limits"] != {
        "maximum_source_lines": 500,
        "active_backend_count": 0,
        "approved_cpu_low_level_allowances": 0,
    }:
        fail("CPU boundary limits drifted")
    if policy["packages"] != {
        "kernel": {
            "name": CPU,
            "version": "0.1.0",
            "runtime": "no_std",
            "dependencies": [],
            "default_features": [],
            "publication": "deferred-crates-io",
            "facade_feature": "none",
        },
        "detector": {
            "name": DETECTOR,
            "version": "0.1.0",
            "runtime": "reserved-std-currently-no_std",
            "dependencies": [CPU],
            "default_features": [],
            "publication": "deferred-crates-io",
            "facade_feature": "none",
        },
    }:
        fail("CPU boundary package contract drifted")
    graph = policy["graph"]
    if (
        graph.get("scalar_owner") != "brynja-crypto"
        or graph.get("facade") != "brynja"
        or graph.get("forbidden_consumers") != list(FORBIDDEN_CONSUMERS)
        or graph.get("third_party_detection_crates") != "forbidden"
        or graph.get("build_time_source_inclusion") != "forbidden"
        or graph.get("implicit_std") != "forbidden"
        or graph.get("os_entropy_and_platform_services") != "forbidden"
    ):
        fail("CPU boundary graph contract drifted")
    if policy["low_level_boundary"] != {
        "current_cpu_allowances": [],
        "approval_scope": "one-exact-symbol",
        "amendment_requires": list(AMENDMENT_REQUIREMENTS),
        "forbidden_mechanisms": list(FORBIDDEN_MECHANISMS),
    }:
        fail("future backend amendment contract drifted")
    if policy["safe_wrapper"] != {"invariants": list(SAFE_WRAPPER_INVARIANTS)}:
        fail("safe wrapper invariant inventory drifted")
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


def validate(root: Path) -> None:
    policy_path = root / POLICY
    policy = read_toml(policy_path)
    validate_policy_shape(policy)
    validate_package_policy(root)
    validate_manifests(root)
    validate_sources(root, policy)
    validate_backends(root, policy)
    if hashlib.sha256(policy_path.read_bytes()).hexdigest() != EXPECTED_POLICY_SHA256:
        fail("CPU security policy changed; reopen boundary review")
