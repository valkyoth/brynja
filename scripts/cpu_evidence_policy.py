#!/usr/bin/env python3
"""Repository binding and deterministic ledger for v0.13.3 CPU evidence."""

from __future__ import annotations

import hashlib
import json
import tomllib
from datetime import datetime, timezone
from pathlib import Path

import cpu_evidence_schema as schema


ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "assurance/cpu-evidence-policy.toml"
ADMISSIONS = ROOT / "security/cpu-backend-admissions.toml"
BOUNDARY = ROOT / "security/cpu-acceleration-boundary.toml"
LEDGER = ROOT / "assurance/cpu-evidence-ledger.json"
EVIDENCE_ROOT = ROOT / "assurance/cpu-evidence"
EXPECTED_POLICY_SHA256 = "4a38b70d658cde7508c0b566dcc01b5f6c5ff8ad1c2867d67af1352cbec1b690"
EXPECTED_ADMISSIONS_SHA256 = "be2b120d289cb7b2b0dee7a51eb8a819268488e221fef7d2fc3d283f6573133b"
BACKEND_FIELDS = {
    "id", "architecture", "required_features", "required_operating_state",
    "native_lanes", "status", "reason",
}
EXPECTED_REASONS = {
    "x86-sha": "no-primitive-implementation-or-native-evidence",
    "x86-aes-gcm": "no-primitive-implementation-or-native-evidence",
    "x86-avx2": "no-primitive-implementation-or-native-evidence",
    "x86-avx512": "no-primitive-implementation-or-native-evidence",
    "aarch64-sha2": "no-primitive-implementation-or-native-evidence",
    "aarch64-aes-gcm": "no-primitive-implementation-or-native-evidence",
    "riscv-vector": "no-primitive-implementation-or-qualifying-native-isa-evidence",
    "riscv-scalar-crypto": "no-primitive-implementation-or-qualifying-native-isa-evidence",
}
ARCHITECTURE_MAP = {"x86_64": "x86_64", "aarch64": "aarch64", "riscv": "riscv64"}


def fail(message: str) -> None:
    raise schema.CpuEvidenceError(message)


def file_hash(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        fail(f"CPU evidence policy input must be a regular file: {path.relative_to(ROOT)}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict:
    maximum = 1_048_576
    return schema.read_toml_bounded(path, maximum)


def validate_admissions(policy: dict, admissions: dict, boundary: dict) -> None:
    schema.exact_keys(admissions, {"schema", "backends"}, "CPU admission register")
    if admissions["schema"] != {"version": 1, "milestone": "0.13.3", "status": "zero-backends-admitted"}:
        fail("CPU admission-register identity drifted")
    lanes = schema.lane_map(policy)
    boundary_backends = {item["id"]: item for item in boundary.get("backends", [])}
    seen = set()
    for backend in admissions["backends"]:
        schema.exact_keys(backend, BACKEND_FIELDS, "CPU admission backend")
        identifier = backend["id"]
        if identifier in seen or identifier not in EXPECTED_REASONS or identifier not in boundary_backends:
            fail("CPU admission backend inventory drifted")
        seen.add(identifier)
        reserved = boundary_backends[identifier]
        expected_architecture = ARCHITECTURE_MAP[reserved["architecture"]]
        if backend["architecture"] != expected_architecture:
            fail(f"CPU admission architecture drifted: {identifier}")
        features = schema.string_list(backend["required_features"], "CPU backend feature bundle", 64)
        operating_state = schema.string_list(
            backend["required_operating_state"], "CPU backend operating state", 64
        )
        if len(features) != len(set(features)) or sorted(features) != sorted(reserved["instructions"]):
            fail(f"CPU admission feature bundle drifted: {identifier}")
        if len(operating_state) != len(set(operating_state)) or sorted(operating_state) != sorted(reserved["abi_preconditions"]):
            fail(f"CPU operating-state requirements drifted: {identifier}")
        if backend["status"] != "unadmitted" or backend["reason"] != EXPECTED_REASONS[identifier]:
            fail(f"CPU backend gained an unsupported admission claim: {identifier}")
        if not backend["native_lanes"] or len(backend["native_lanes"]) != len(set(backend["native_lanes"])):
            fail(f"CPU backend native lane set is empty or duplicated: {identifier}")
        for lane_id in backend["native_lanes"]:
            lane = lanes.get(lane_id)
            if lane is None or lane["execution_kind"] != "native" or lane["architecture"] != backend["architecture"]:
                fail(f"CPU backend references an invalid native lane: {identifier}")
    if seen != set(EXPECTED_REASONS):
        fail("CPU admission backend inventory is incomplete")
    if boundary.get("limits", {}).get("active_backend_count") != 0:
        fail("CPU boundary and admission register disagree on active backends")


def validate_repository_binding() -> None:
    checks = (ROOT / "scripts/checks.sh").read_text(encoding="utf-8")
    for command in (
        "python3 scripts/check-cpu-evidence.py",
        "python3 scripts/test-cpu-evidence.py",
        "scripts/check-cpu-admission-fixture.sh",
    ):
        if checks.count(command) != 1:
            fail(f"ordinary checks do not bind CPU evidence command exactly once: {command}")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    command = "run: python scripts/test-cpu-evidence.py"
    if workflow.count(command) != 1:
        fail("native host CI does not run CPU evidence fixtures")
    for relative in (
        "scripts/cpu_evidence_schema.py",
        "scripts/cpu_evidence_policy.py",
        "scripts/check-cpu-evidence.py",
        "scripts/validate-cpu-evidence.py",
        "scripts/test-cpu-evidence.py",
        "scripts/cpu_evidence_fixture_tests.py",
        "scripts/check-cpu-admission-fixture.sh",
    ):
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            fail(f"missing regular CPU evidence runner: {relative}")
        if len(path.read_text(encoding="utf-8").splitlines()) > 500:
            fail(f"CPU evidence code exceeds 500 lines: {relative}")


def evidence_manifests(maximum: int = 256) -> list[Path]:
    if not EVIDENCE_ROOT.exists():
        return []
    if EVIDENCE_ROOT.is_symlink() or not EVIDENCE_ROOT.is_dir():
        fail("CPU evidence root must be a real directory")
    paths = []
    for entry in EVIDENCE_ROOT.iterdir():
        if entry.name == "README.md":
            if not entry.is_file() or entry.is_symlink():
                fail("CPU evidence README must be a regular file")
            continue
        if len(paths) == maximum:
            fail("CPU evidence manifest inventory exceeds its bound")
        manifest = entry / "manifest.toml"
        if not entry.is_dir() or entry.is_symlink() or not manifest.is_file() or manifest.is_symlink():
            fail(f"unexpected CPU evidence entry: {entry.relative_to(ROOT)}")
        paths.append(manifest)
    return sorted(paths)


def validate_all_records(policy: dict, admissions: dict, evaluated: datetime | None = None) -> list[dict]:
    now = evaluated or datetime.now(timezone.utc)
    results = []
    maximum = policy["limits"]["maximum_manifest_bytes"]
    for manifest in evidence_manifests(policy["limits"]["maximum_evidence_manifests"]):
        record = schema.read_toml_bounded(manifest, maximum)
        results.append(schema.validate_record(record, policy, admissions, manifest.parent, now))
    return results


def load_and_validate() -> tuple[dict, dict]:
    policy = read(POLICY)
    admissions = read(ADMISSIONS)
    boundary = read(BOUNDARY)
    schema.validate_policy(policy)
    validate_admissions(policy, admissions, boundary)
    if file_hash(POLICY) != EXPECTED_POLICY_SHA256:
        fail("CPU evidence policy changed; reopen review")
    if file_hash(ADMISSIONS) != EXPECTED_ADMISSIONS_SHA256:
        fail("CPU admission register changed; reopen review")
    validate_repository_binding()
    return policy, admissions


def build_ledger(policy: dict, admissions: dict) -> dict:
    lanes = [
        {
            "architecture": lane["architecture"],
            "execution_kind": lane["execution_kind"],
            "id": lane["id"],
            "status": lane["status"],
        }
        for lane in policy["lanes"]
    ]
    backends = [
        {
            "architecture": backend["architecture"],
            "id": backend["id"],
            "native_lanes": backend["native_lanes"],
            "required_features": backend["required_features"],
            "required_operating_state": backend["required_operating_state"],
            "reason": backend["reason"],
            "status": backend["status"],
        }
        for backend in admissions["backends"]
    ]
    manifests = []
    native_result_count = 0
    maximum = policy["limits"]["maximum_manifest_bytes"]
    for path in evidence_manifests(policy["limits"]["maximum_evidence_manifests"]):
        record = schema.read_toml_bounded(path, maximum)
        if record["run"]["execution_kind"] == "native":
            native_result_count += 1
        manifests.append({
            "admission_eligible": record["claims"]["admission_eligible"],
            "backend": record["run"]["backend"],
            "lane": record["run"]["lane"],
            "path": str(path.relative_to(ROOT)),
            "run": record["run"]["id"],
            "sha256": file_hash(path),
        })
    return {
        "schema": {"version": 1, "milestone": "0.13.3"},
        "claims": {
            "admitted_backend_count": sum(item["status"] == "admitted" for item in admissions["backends"]),
            "native_result_count": native_result_count,
            "portable_scalar_blocked_by_unavailable_lane": False,
            "qemu_can_satisfy_native_evidence": False,
        },
        "policy": {
            "path": str(POLICY.relative_to(ROOT)),
            "sha256": file_hash(POLICY),
        },
        "admissions": {
            "path": str(ADMISSIONS.relative_to(ROOT)),
            "sha256": file_hash(ADMISSIONS),
        },
        "harnesses": [item["id"] for item in policy["harnesses"]],
        "lanes": lanes,
        "backends": backends,
        "evidence_manifests": manifests,
    }


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
