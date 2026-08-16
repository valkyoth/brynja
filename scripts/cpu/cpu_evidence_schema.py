#!/usr/bin/env python3
"""Fail-closed schema and admission evaluation for CPU-backend evidence."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "assurance"))
import assurance_io


HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
JSON_INTEGER_MIN = -(2**63)
JSON_INTEGER_MAX = 2**63 - 1
TOP_LEVEL = {"schema", "run", "cpu", "environment", "workload", "results", "artifacts", "claims"}
SCHEMA_FIELDS = {"version", "kind"}
RUN_FIELDS = {
    "id", "created_utc", "source_commit", "lane", "backend", "primitive",
    "operation", "runner_owner", "execution_kind", "status",
}
CPU_FIELDS = {
    "architecture", "vendor", "model", "family", "stepping",
    "microcode_or_firmware", "logical_cpu", "logical_cpu_identity_sha256",
    "observed_features", "operating_state",
}
ENVIRONMENT_FIELDS = {
    "os", "kernel", "virtualization", "compiler", "compiler_commit", "target",
    "rustflags", "frequency_policy", "clock_source", "isolation", "binary_sha256",
}
WORKLOAD_FIELDS = {
    "distribution", "sizes", "corpus_sha256", "schedule", "schedule_sha256",
    "sample_count",
}
RESULT_FIELDS = {
    "forced_backend", "required_mode", "unsupported_feature", "known_answer",
    "quarantine", "scalar_differential", "concurrency_isolation", "emitted_code", "side_channel",
    "code_size_increase_bytes", "cold_start_nanoseconds",
    "latency_median_nanoseconds", "latency_p95_nanoseconds",
    "throughput_bytes_per_second", "coefficient_of_variation_ppm",
    "speedup_ppm", "order_imbalance", "cpu_identity_count",
}
ARTIFACT_FIELDS = {"harness", "path", "sha256", "bytes"}
CLAIM_FIELDS = {
    "native_performance", "native_side_channel", "admission_eligible",
    "residual_gaps",
}
HARNESS_RESULT_FIELDS = {
    "forced-backend": ("forced_backend",),
    "required-mode": ("required_mode",),
    "unsupported-feature": ("unsupported_feature",),
    "known-answer": ("known_answer",),
    "quarantine": ("quarantine",),
    "scalar-differential": ("scalar_differential",),
    "concurrency-isolation": ("concurrency_isolation",),
    "emitted-code": ("emitted_code",),
    "code-size": ("code_size_increase_bytes",),
    "cold-start": ("cold_start_nanoseconds",),
    "latency": (
        "latency_median_nanoseconds", "latency_p95_nanoseconds",
        "coefficient_of_variation_ppm", "order_imbalance", "cpu_identity_count",
    ),
    "throughput": ("throughput_bytes_per_second", "speedup_ppm"),
    "side-channel": ("side_channel",),
}
HARNESS_ARTIFACT_FIELDS = {
    "schema", "harness", "status", "run", "source_commit", "binary_sha256",
    "backend", "lane", "primitive", "operation", "context_sha256", "measurements",
}


class CpuEvidenceError(RuntimeError):
    """CPU evidence or an admission claim failed closed."""


def fail(message: str) -> None:
    raise CpuEvidenceError(message)


def exact_keys(value: dict, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} fields drifted")


def bounded_integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        fail(f"{label} is not a bounded integer")
    return value


def nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        fail(f"{label} is empty or unbounded")
    return value


def string_list(value: object, label: str, maximum_items: int) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum_items:
        fail(f"{label} is empty or unbounded")
    if not all(isinstance(item, str) and 0 < len(item) <= 256 for item in value):
        fail(f"{label} contains an invalid value")
    return value


def read_toml_bounded(path: Path, maximum_bytes: int) -> dict:
    try:
        data = assurance_io.read_bounded_regular(path, maximum_bytes)
        return tomllib.loads(data.decode("utf-8"))
    except (OSError, UnicodeError, RuntimeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read evidence input {path}: {error}")


def parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        fail("evidence timestamp must be exact UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        fail(f"invalid evidence timestamp: {error}")


def validate_age(created: datetime, evaluated: datetime, maximum_days: int) -> None:
    if evaluated.tzinfo is None:
        fail("evaluation timestamp must be timezone-aware")
    age = evaluated.astimezone(timezone.utc) - created
    if age.total_seconds() < 0:
        fail("evidence timestamp is in the future")
    if age.total_seconds() > maximum_days * 86_400:
        fail("evidence is stale")


def validate_policy(policy: dict) -> None:
    exact_keys(policy, {"schema", "limits", "admission", "record_schema", "workload", "harnesses", "lanes"}, "CPU evidence policy")
    if policy["schema"] != {"version": 1, "milestone": "0.13.3", "status": "admission-contracts-only"}:
        fail("CPU evidence schema identity drifted")
    expected_limits = {
        "maximum_manifest_bytes": 1_048_576,
        "maximum_evidence_manifests": 256,
        "maximum_raw_artifact_bytes": 16_777_216,
        "maximum_total_raw_artifact_bytes": 67_108_864,
        "maximum_evidence_age_days": 90,
        "minimum_benchmark_samples": 31,
        "maximum_benchmark_samples": 100_000,
        "maximum_coefficient_of_variation_ppm": 100_000,
        "maximum_order_imbalance": 1,
        "minimum_speedup_ppm": 1_050_000,
        "maximum_code_size_increase_bytes": 65_536,
        "maximum_cold_start_nanoseconds": 5_000_000,
        "minimum_machine_integer": JSON_INTEGER_MIN,
        "maximum_machine_integer": JSON_INTEGER_MAX,
    }
    if policy["limits"] != expected_limits:
        fail("CPU evidence limits drifted")
    expected_admission = {
        "default": "unadmitted", "scalar_build_independent": True,
        "native_performance_required": True, "native_side_channel_required": True,
        "emulation_role": "supplemental-instruction-coverage-only",
        "unavailable_lane_result": "unadmitted", "unmeasured_backend_result": "unadmitted",
        "mixed_cpu_runs": "forbidden", "non_finite_measurements": "forbidden",
        "raw_results": "machine-readable-schema-and-hash-bound-regular-files",
        "provenance_role": "recorded-not-authenticated",
        "trusted_runner_attestation": "required-no-verifier-admitted",
        "candidate_admission": "forbidden-until-authenticated-semantic-verifier",
        "benchmark_schedule": "deterministic-balanced-interleaved",
        "frequency_policy": "recorded-and-stable",
    }
    if policy["admission"] != expected_admission:
        fail("CPU admission semantics drifted")
    schema = policy["record_schema"]
    expected_schema = {
        "top_level": sorted(TOP_LEVEL), "schema": sorted(SCHEMA_FIELDS),
        "run": sorted(RUN_FIELDS), "cpu": sorted(CPU_FIELDS),
        "environment": sorted(ENVIRONMENT_FIELDS), "workload": sorted(WORKLOAD_FIELDS),
        "results": sorted(RESULT_FIELDS), "artifact": sorted(ARTIFACT_FIELDS),
        "claims": sorted(CLAIM_FIELDS),
    }
    for key, expected in expected_schema.items():
        if sorted(schema.get(key, [])) != expected:
            fail(f"machine-readable record schema drifted: {key}")
    harnesses = policy["harnesses"]
    ids = []
    for harness in harnesses:
        exact_keys(harness, {"id", "class", "native_required", "failure"}, "CPU harness")
        if IDENTIFIER.fullmatch(harness["id"]) is None or not harness["failure"]:
            fail("CPU harness identity or failure mode is invalid")
        ids.append(harness["id"])
    required = {
        "forced-backend", "required-mode", "unsupported-feature", "known-answer", "quarantine",
        "scalar-differential", "concurrency-isolation", "emitted-code", "code-size",
        "cold-start", "latency", "throughput", "side-channel",
    }
    if set(ids) != required or len(ids) != len(set(ids)):
        fail("CPU harness inventory is incomplete or duplicated")
    mapped_fields = [
        field
        for identifier in required
        for field in HARNESS_RESULT_FIELDS.get(identifier, ())
    ]
    if set(HARNESS_RESULT_FIELDS) != required or set(mapped_fields) != RESULT_FIELDS or len(mapped_fields) != len(set(mapped_fields)):
        fail("machine-readable harness result coverage drifted")
    validate_lanes(policy["lanes"])


def validate_lanes(lanes: list[dict]) -> None:
    expected_ids = {
        "local-amd-x86_64", "aws-intel-x86_64", "apple-m2-aarch64",
        "aws-aarch64", "riscv64-cloud", "qemu-x86_64", "qemu-aarch64",
        "qemu-riscv64",
    }
    seen = set()
    for lane in lanes:
        exact_keys(lane, {"id", "execution_kind", "architecture", "os", "runner_owner", "provider", "selection", "vendor_rule", "status"}, "CPU lane")
        if lane["id"] in seen or lane["id"] not in expected_ids:
            fail("CPU lane inventory drifted")
        seen.add(lane["id"])
        if lane["execution_kind"] == "emulated":
            if lane["status"] != "supplemental-only" or lane["provider"] != "qemu":
                fail("emulated lane gained native admission authority")
            if lane["selection"] != "explicit-emulated-cpu-model":
                fail("emulated CPU model selection drifted")
        elif lane["execution_kind"] == "native":
            if lane["status"] not in {"registered-unmeasured", "registered-unavailable"}:
                fail("native lane status is not fail-closed")
            if "observed-" not in lane["selection"]:
                fail("native lane selection must use observed capabilities")
        else:
            fail("unknown CPU lane execution kind")
        vendor_rule = lane["vendor_rule"]
        if vendor_rule != "recorded-nonempty" and not vendor_rule.startswith("exact:"):
            fail("CPU lane vendor rule drifted")
    if seen != expected_ids:
        fail("CPU lane inventory is incomplete")


def lane_map(policy: dict) -> dict[str, dict]:
    return {lane["id"]: lane for lane in policy["lanes"]}


def backend_map(admissions: dict) -> dict[str, dict]:
    return {backend["id"]: backend for backend in admissions["backends"]}


def cpu_identity_digest(cpu: dict) -> str:
    identity = {
        key: cpu[key]
        for key in CPU_FIELDS
        if key != "logical_cpu_identity_sha256"
    }
    identity["observed_features"] = sorted(identity["observed_features"])
    identity["operating_state"] = sorted(identity["operating_state"])
    encoded = json.dumps(identity, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def canonical_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def harness_context(record: dict) -> str:
    return canonical_digest({
        key: record[key]
        for key in ("run", "cpu", "environment", "workload", "results")
    })


def parse_harness_artifact(data: bytes, harness: str, record: dict) -> None:
    def unique_object(pairs: list[tuple[str, object]]) -> dict:
        value = {}
        for key, item in pairs:
            if key in value:
                fail("machine-readable harness artifact has duplicate fields")
            value[key] = item
        return value

    def parse_bounded_integer(text: str) -> int:
        digits = text.removeprefix("-")
        if len(digits) > 19:
            fail("machine-readable harness integer exceeds its bound")
        value = int(text)
        if not JSON_INTEGER_MIN <= value <= JSON_INTEGER_MAX:
            fail("machine-readable harness integer exceeds its bound")
        return value

    def reject_float(_text: str) -> float:
        fail("floating-point JSON values are forbidden")

    def reject_constant(value: str) -> float:
        fail(f"non-finite JSON value is forbidden: {value}")

    try:
        payload = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_int=parse_bounded_integer,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        fail(f"machine-readable harness artifact is invalid: {harness}: {error}")
    exact_keys(payload, HARNESS_ARTIFACT_FIELDS, "machine-readable harness artifact")
    fields = HARNESS_RESULT_FIELDS[harness]
    status_fields = [field for field in fields if isinstance(record["results"][field], str)]
    expected_status = record["results"][status_fields[0]] if status_fields else "pass"
    expected_measurements = {
        field: record["results"][field]
        for field in fields
        if field not in status_fields
    }
    expected_identity = {
        "schema": 1,
        "harness": harness,
        "status": expected_status,
        "run": record["run"]["id"],
        "source_commit": record["run"]["source_commit"],
        "binary_sha256": record["environment"]["binary_sha256"],
        "backend": record["run"]["backend"],
        "lane": record["run"]["lane"],
        "primitive": record["run"]["primitive"],
        "operation": record["run"]["operation"],
        "context_sha256": harness_context(record),
        "measurements": expected_measurements,
    }
    if canonical_json(payload) != canonical_json(expected_identity):
        fail(f"harness artifact semantics differ from the manifest: {harness}")


def validate_artifacts(artifacts: object, policy: dict, artifact_root: Path, record: dict) -> None:
    if not isinstance(artifacts, list):
        fail("raw artifact inventory must be an array")
    required = {item["id"] for item in policy["harnesses"]}
    seen = set()
    maximum = policy["limits"]["maximum_raw_artifact_bytes"]
    maximum_total = policy["limits"]["maximum_total_raw_artifact_bytes"]
    total = 0
    raw_root = artifact_root / "raw"
    if not artifact_root.is_dir() or artifact_root.is_symlink() or not raw_root.is_dir() or raw_root.is_symlink():
        fail("evidence and raw-artifact directories must be real directories")
    for artifact in artifacts:
        exact_keys(artifact, ARTIFACT_FIELDS, "raw artifact")
        harness = artifact["harness"]
        if not isinstance(harness, str) or harness in seen or harness not in required:
            fail("raw artifact harness is duplicated or unknown")
        seen.add(harness)
        relative = PurePosixPath(nonempty(artifact["path"], "raw artifact path"))
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 2 or relative.parts[0] != "raw":
            fail("raw artifact path escapes its evidence directory")
        path = artifact_root.joinpath(*relative.parts)
        size = bounded_integer(artifact["bytes"], "raw artifact byte count", 1, maximum)
        try:
            data = assurance_io.read_bounded_regular(path, maximum)
        except RuntimeError as error:
            fail(f"cannot securely read raw artifact {relative}: {error}")
        if len(data) != size:
            fail(f"raw artifact size mismatch: {relative}")
        total += len(data)
        if total > maximum_total:
            fail("raw artifact set exceeds its total byte bound")
        digest = hashlib.sha256(data).hexdigest()
        if not isinstance(artifact["sha256"], str) or HEX_64.fullmatch(artifact["sha256"]) is None or digest != artifact["sha256"]:
            fail(f"raw artifact checksum mismatch: {relative}")
        parse_harness_artifact(data, harness, record)
    if seen != required:
        fail("raw artifact inventory is incomplete")


def validate_record(record: dict, policy: dict, admissions: dict, artifact_root: Path, evaluated: datetime) -> dict:
    exact_keys(record, TOP_LEVEL, "CPU evidence record")
    exact_keys(record["schema"], SCHEMA_FIELDS, "CPU evidence schema")
    if record["schema"] != {"version": 1, "kind": "cpu-backend-admission"}:
        fail("CPU evidence record schema drifted")
    for key, fields in (("run", RUN_FIELDS), ("cpu", CPU_FIELDS), ("environment", ENVIRONMENT_FIELDS), ("workload", WORKLOAD_FIELDS), ("results", RESULT_FIELDS), ("claims", CLAIM_FIELDS)):
        exact_keys(record[key], fields, f"CPU evidence {key}")
    run = record["run"]
    if not isinstance(run["id"], str) or IDENTIFIER.fullmatch(run["id"]) is None or not isinstance(run["source_commit"], str) or HEX_40.fullmatch(run["source_commit"]) is None:
        fail("run identity or source commit is invalid")
    if run["status"] != "complete":
        fail("only complete evidence can be evaluated")
    nonempty(run["primitive"], "primitive")
    nonempty(run["operation"], "operation")
    nonempty(run["lane"], "lane")
    nonempty(run["backend"], "backend")
    created = parse_utc(run["created_utc"])
    validate_age(created, evaluated, policy["limits"]["maximum_evidence_age_days"])
    lanes = lane_map(policy)
    backends = backend_map(admissions)
    if run["lane"] not in lanes or run["backend"] not in backends:
        fail("unknown lane or backend")
    lane = lanes[run["lane"]]
    backend = backends[run["backend"]]
    if run["execution_kind"] != lane["execution_kind"] or run["runner_owner"] != lane["runner_owner"]:
        fail("fabricated native lane or runner ownership")
    cpu = record["cpu"]
    if cpu["architecture"] != lane["architecture"] or backend["architecture"] != lane["architecture"]:
        fail("CPU, lane, and backend architectures differ")
    observed_features = string_list(cpu["observed_features"], "observed features", 64)
    operating_state = string_list(cpu["operating_state"], "operating state", 64)
    if sorted(observed_features) != sorted(backend["required_features"]):
        fail("observed feature evidence is incomplete or overbroad")
    if sorted(operating_state) != sorted(backend["required_operating_state"]):
        fail("required ABI or vector operating state is unavailable")
    for field in ("vendor", "model", "family", "stepping", "microcode_or_firmware"):
        nonempty(cpu[field], f"CPU {field}")
    bounded_integer(cpu["logical_cpu"], "logical CPU number", 0, 2**32 - 1)
    vendor_rule = lane["vendor_rule"]
    if vendor_rule.startswith("exact:") and cpu["vendor"] != vendor_rule.removeprefix("exact:"):
        fail("CPU vendor differs from the registered lane")
    if len(observed_features) != len(set(observed_features)) or len(operating_state) != len(set(operating_state)):
        fail("CPU feature or operating-state evidence is duplicated")
    if not isinstance(cpu["logical_cpu_identity_sha256"], str) or HEX_64.fullmatch(cpu["logical_cpu_identity_sha256"]) is None or cpu_identity_digest(cpu) != cpu["logical_cpu_identity_sha256"]:
        fail("logical CPU identity or operating-state evidence is missing")
    environment = record["environment"]
    if environment["os"] != lane["os"] or not isinstance(environment["compiler_commit"], str) or HEX_40.fullmatch(environment["compiler_commit"]) is None:
        fail("OS or compiler provenance differs from the registered lane")
    if not isinstance(environment["binary_sha256"], str) or HEX_64.fullmatch(environment["binary_sha256"]) is None:
        fail("measured binary hash is invalid")
    for field in ("kernel", "virtualization", "compiler", "target", "frequency_policy", "clock_source", "isolation"):
        nonempty(environment[field], f"environment {field}")
    if not isinstance(environment["rustflags"], list) or len(environment["rustflags"]) > 64 or not all(isinstance(item, str) and len(item) <= 256 for item in environment["rustflags"]):
        fail("compiler flags must be an explicit string array")
    workload = record["workload"]
    expected_workload = policy["workload"]
    if workload["distribution"] != expected_workload["distribution"] or workload["sizes"] != expected_workload["sizes"]:
        fail("workload size distribution drifted")
    if workload["schedule"] != policy["admission"]["benchmark_schedule"]:
        fail("benchmark schedule permits order bias")
    if not isinstance(workload["corpus_sha256"], str) or not isinstance(workload["schedule_sha256"], str) or HEX_64.fullmatch(workload["corpus_sha256"]) is None or HEX_64.fullmatch(workload["schedule_sha256"]) is None:
        fail("workload corpus or schedule hash is invalid")
    limits = policy["limits"]
    bounded_integer(workload["sample_count"], "sample count", limits["minimum_benchmark_samples"], limits["maximum_benchmark_samples"])
    results = record["results"]
    for field in ("forced_backend", "required_mode", "unsupported_feature", "known_answer", "quarantine", "scalar_differential", "concurrency_isolation", "emitted_code"):
        if results[field] != expected_workload["required_result"]:
            fail(f"required harness did not pass: {field}")
    if results["side_channel"] != expected_workload["required_side_channel_result"]:
        fail("side-channel harness did not pass")
    numeric_limits = {
        "code_size_increase_bytes": (0, limits["maximum_code_size_increase_bytes"]),
        "cold_start_nanoseconds": (0, limits["maximum_cold_start_nanoseconds"]),
        "latency_median_nanoseconds": (1, 2**63 - 1),
        "latency_p95_nanoseconds": (1, 2**63 - 1),
        "throughput_bytes_per_second": (1, 2**63 - 1),
        "coefficient_of_variation_ppm": (0, limits["maximum_coefficient_of_variation_ppm"]),
        "speedup_ppm": (limits["minimum_speedup_ppm"], 2**63 - 1),
        "order_imbalance": (0, limits["maximum_order_imbalance"]),
        "cpu_identity_count": (1, 1),
    }
    for field, (lower, upper) in numeric_limits.items():
        value = results[field]
        if isinstance(value, float) and not math.isfinite(value):
            fail(f"non-finite measurement: {field}")
        bounded_integer(value, field, lower, upper)
    if results["latency_p95_nanoseconds"] < results["latency_median_nanoseconds"]:
        fail("latency percentile ordering is invalid")
    if environment["frequency_policy"] != "fixed-and-recorded":
        fail("frequency policy is not stable and recorded")
    validate_artifacts(record["artifacts"], policy, artifact_root, record)
    claims = record["claims"]
    if claims["residual_gaps"] != [expected_workload["required_residual_gap"]]:
        fail("statistical residual gap is missing or changed")
    if backend["status"] != "unadmitted":
        fail("trusted-runner attestation verifier is unavailable; candidate admission is forbidden")
    if claims["native_performance"] is not False or claims["native_side_channel"] is not False:
        fail("unauthenticated evidence cannot make native performance or side-channel claims")
    if claims["admission_eligible"] is not False:
        fail("unauthenticated evidence cannot make an admission claim")
    return {"run": run["id"], "backend": run["backend"], "lane": run["lane"], "admission_eligible": False}
