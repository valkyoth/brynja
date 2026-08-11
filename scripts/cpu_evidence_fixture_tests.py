#!/usr/bin/env python3
"""Adversarial fixtures for the v0.13.3 CPU evidence schema."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import cpu_evidence_schema as schema


EVALUATED = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc)
HASH = "11" * 32
COMMIT = "22" * 20


def expect_failure(message: str, callback) -> None:
    try:
        callback()
    except schema.CpuEvidenceError as error:
        if message not in str(error):
            raise AssertionError(f"expected {message!r}, received {error!s}") from error
    else:
        raise AssertionError(f"expected CPU evidence rejection: {message}")


def make_record(
    policy: dict,
    admissions: dict,
    root: Path,
    lane_id: str = "local-amd-x86_64",
    backend_id: str | None = None,
) -> dict:
    lanes = schema.lane_map(policy)
    lane = lanes[lane_id]
    backend = next(
        item for item in admissions["backends"]
        if item["architecture"] == lane["architecture"]
        and (backend_id is None or item["id"] == backend_id)
    )
    raw = root / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    vendor_rule = lane["vendor_rule"]
    vendor = vendor_rule.removeprefix("exact:") if vendor_rule.startswith("exact:") else "fixture-vendor"
    record = {
        "schema": {"version": 1, "kind": "cpu-backend-admission"},
        "run": {
            "id": "fixture-run-1", "created_utc": "2026-08-11T10:00:00Z",
            "source_commit": COMMIT, "lane": lane_id, "backend": backend["id"],
            "primitive": "fixture-only", "operation": "fixture-transform",
            "runner_owner": lane["runner_owner"], "execution_kind": lane["execution_kind"],
            "status": "complete",
        },
        "cpu": {
            "architecture": lane["architecture"], "vendor": vendor,
            "model": "fixture-model", "family": "fixture-family", "stepping": "fixture-step",
            "microcode_or_firmware": "fixture-firmware",
            "logical_cpu": 0, "logical_cpu_identity_sha256": HASH,
            "observed_features": list(backend["required_features"]),
            "operating_state": list(backend["required_operating_state"]),
        },
        "environment": {
            "os": lane["os"], "kernel": "fixture-kernel", "virtualization": "none",
            "compiler": "rustc 1.97.1", "compiler_commit": COMMIT,
            "target": f"{lane['architecture']}-fixture", "rustflags": ["-Copt-level=3"],
            "frequency_policy": "fixed-and-recorded", "clock_source": "monotonic-fixture",
            "isolation": "dedicated-fixture", "binary_sha256": HASH,
        },
        "workload": {
            "distribution": policy["workload"]["distribution"],
            "sizes": list(policy["workload"]["sizes"]), "corpus_sha256": HASH,
            "schedule": policy["admission"]["benchmark_schedule"],
            "schedule_sha256": HASH, "sample_count": 31,
        },
        "results": {
            "forced_backend": "pass", "required_mode": "pass",
            "unsupported_feature": "pass", "known_answer": "pass",
            "quarantine": "pass", "scalar_differential": "pass",
            "concurrency_isolation": "pass", "emitted_code": "pass",
            "side_channel": "pass-no-detectable-leakage",
            "code_size_increase_bytes": 1024, "cold_start_nanoseconds": 1000,
            "latency_median_nanoseconds": 100, "latency_p95_nanoseconds": 120,
            "throughput_bytes_per_second": 1_000_000,
            "coefficient_of_variation_ppm": 10_000, "speedup_ppm": 1_100_000,
            "order_imbalance": 1, "cpu_identity_count": 1,
        },
        "artifacts": [],
        "claims": {
            "native_performance": False, "native_side_channel": False,
            "admission_eligible": False,
            "residual_gaps": ["statistical-testing-is-not-proof"],
        },
    }
    record["cpu"]["logical_cpu_identity_sha256"] = schema.cpu_identity_digest(record["cpu"])
    context = schema.harness_context(record)
    for harness in policy["harnesses"]:
        identifier = harness["id"]
        fields = schema.HARNESS_RESULT_FIELDS[identifier]
        status_fields = [field for field in fields if isinstance(record["results"][field], str)]
        payload = {
            "schema": 1,
            "harness": identifier,
            "status": record["results"][status_fields[0]] if status_fields else "pass",
            "run": record["run"]["id"],
            "source_commit": record["run"]["source_commit"],
            "binary_sha256": record["environment"]["binary_sha256"],
            "backend": record["run"]["backend"],
            "lane": record["run"]["lane"],
            "primitive": record["run"]["primitive"],
            "operation": record["run"]["operation"],
            "context_sha256": context,
            "measurements": {
                field: record["results"][field]
                for field in fields
                if field not in status_fields
            },
        }
        name = f"{identifier}.json"
        data = (json.dumps(payload, sort_keys=True) + "\n").encode()
        (raw / name).write_bytes(data)
        record["artifacts"].append({
            "harness": identifier,
            "path": f"raw/{name}",
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        })
    return record


def rewrite_artifact(root: Path, record: dict, index: int, mutate) -> None:
    artifact = record["artifacts"][index]
    path = root / artifact["path"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    data = (json.dumps(payload, sort_keys=True) + "\n").encode()
    path.write_bytes(data)
    artifact["sha256"] = hashlib.sha256(data).hexdigest()
    artifact["bytes"] = len(data)


def run(policy: dict, admissions: dict, root: Path, record: dict) -> dict:
    return schema.validate_record(record, policy, admissions, root, EVALUATED)


def test(policy: dict, admissions: dict, root: Path) -> None:
    record = make_record(policy, admissions, root)
    assert run(policy, admissions, root, record)["admission_eligible"] is False

    candidate = copy.deepcopy(admissions)
    target = next(item for item in candidate["backends"] if item["id"] == record["run"]["backend"])
    target["status"] = "candidate"
    expect_failure(
        "attestation verifier is unavailable",
        lambda: run(policy, candidate, root, copy.deepcopy(record)),
    )

    cases = (
        ("stale", lambda value: value["run"].update(created_utc="2026-01-01T00:00:00Z"), "evidence is stale"),
        ("future", lambda value: value["run"].update(created_utc="2026-08-12T00:00:00Z"), "timestamp is in the future"),
        ("features", lambda value: value["cpu"].update(observed_features=[]), "observed features"),
        ("native", lambda value: value["run"].update(execution_kind="emulated"), "fabricated native lane"),
        ("owner", lambda value: value["run"].update(runner_owner="untrusted"), "runner ownership"),
        ("type", lambda value: value["cpu"].update(observed_features=[["sha"]]), "invalid value"),
        ("vendor", lambda value: value["cpu"].update(vendor="wrong-vendor"), "CPU vendor"),
        ("mixed", lambda value: value["results"].update(cpu_identity_count=2), "cpu_identity_count"),
        ("noise", lambda value: value["results"].update(coefficient_of_variation_ppm=100001), "coefficient_of_variation_ppm"),
        ("speed", lambda value: value["results"].update(speedup_ppm=1049999), "speedup_ppm"),
        ("order", lambda value: value["results"].update(order_imbalance=2), "order_imbalance"),
        ("schedule", lambda value: value["workload"].update(schedule="backend-first"), "order bias"),
        ("sample", lambda value: value["workload"].update(sample_count=30), "sample count"),
        ("size", lambda value: value["results"].update(code_size_increase_bytes=65537), "code_size_increase_bytes"),
        ("cold", lambda value: value["results"].update(cold_start_nanoseconds=5000001), "cold_start_nanoseconds"),
        ("kat", lambda value: value["results"].update(known_answer="fail"), "known_answer"),
        ("required", lambda value: value["results"].update(required_mode="scalar-fallback"), "required_mode"),
        ("quarantine", lambda value: value["results"].update(quarantine="fail"), "quarantine"),
        ("differential", lambda value: value["results"].update(scalar_differential="mismatch"), "scalar_differential"),
        ("concurrency", lambda value: value["results"].update(concurrency_isolation="fail"), "concurrency_isolation"),
        ("side-channel", lambda value: value["results"].update(side_channel="inconclusive"), "side-channel"),
        ("residual", lambda value: value["claims"].update(residual_gaps=[]), "residual gap"),
    )
    for _name, mutate, message in cases:
        broken = copy.deepcopy(record)
        mutate(broken)
        expect_failure(message, lambda broken=broken: run(policy, admissions, root, broken))

    non_finite = copy.deepcopy(record)
    non_finite["results"]["latency_median_nanoseconds"] = float("nan")
    expect_failure("non-finite measurement", lambda: run(policy, admissions, root, non_finite))

    bad_identity = copy.deepcopy(record)
    bad_identity["cpu"]["model"] = "substituted-model"
    expect_failure("logical CPU identity", lambda: run(policy, admissions, root, bad_identity))

    bad_percentile = copy.deepcopy(record)
    bad_percentile["results"]["latency_p95_nanoseconds"] = 99
    expect_failure("percentile ordering", lambda: run(policy, admissions, root, bad_percentile))

    bad_hash = copy.deepcopy(record)
    bad_hash["artifacts"][0]["sha256"] = "00" * 32
    expect_failure("checksum mismatch", lambda: run(policy, admissions, root, bad_hash))

    forged = copy.deepcopy(record)
    forged_path = root / forged["artifacts"][0]["path"]
    forged_data = b"FAIL: harness was never executed\n"
    forged_path.write_bytes(forged_data)
    forged["artifacts"][0]["sha256"] = hashlib.sha256(forged_data).hexdigest()
    forged["artifacts"][0]["bytes"] = len(forged_data)
    expect_failure("machine-readable harness artifact is invalid", lambda: run(policy, admissions, root, forged))

    # Restore the shared fixture artifact after the deliberate on-disk forgery.
    record = make_record(policy, admissions, root)

    failed_artifact = copy.deepcopy(record)
    rewrite_artifact(root, failed_artifact, 0, lambda payload: payload.update(status="fail"))
    expect_failure("semantics differ", lambda: run(policy, admissions, root, failed_artifact))

    record = make_record(policy, admissions, root)
    duplicate_json = copy.deepcopy(record)
    duplicate_path = root / duplicate_json["artifacts"][0]["path"]
    duplicate_data = b'{"schema":1,"schema":1}\n'
    duplicate_path.write_bytes(duplicate_data)
    duplicate_json["artifacts"][0]["sha256"] = hashlib.sha256(duplicate_data).hexdigest()
    duplicate_json["artifacts"][0]["bytes"] = len(duplicate_data)
    expect_failure("duplicate fields", lambda: run(policy, admissions, root, duplicate_json))

    record = make_record(policy, admissions, root)
    wrong_source = copy.deepcopy(record)
    rewrite_artifact(root, wrong_source, 0, lambda payload: payload.update(source_commit="00" * 20))
    expect_failure("semantics differ", lambda: run(policy, admissions, root, wrong_source))

    record = make_record(policy, admissions, root)
    wrong_measurement = copy.deepcopy(record)
    latency = next(index for index, item in enumerate(wrong_measurement["artifacts"]) if item["harness"] == "latency")
    rewrite_artifact(root, wrong_measurement, latency, lambda payload: payload["measurements"].update(latency_p95_nanoseconds=1))
    expect_failure("semantics differ", lambda: run(policy, admissions, root, wrong_measurement))

    record = make_record(policy, admissions, root)
    boolean_measurement = copy.deepcopy(record)
    latency = next(index for index, item in enumerate(boolean_measurement["artifacts"]) if item["harness"] == "latency")
    rewrite_artifact(root, boolean_measurement, latency, lambda payload: payload["measurements"].update(order_imbalance=True))
    expect_failure("semantics differ", lambda: run(policy, admissions, root, boolean_measurement))

    record = make_record(policy, admissions, root)
    wrong_binary = copy.deepcopy(record)
    wrong_binary["environment"]["binary_sha256"] = "33" * 32
    expect_failure("semantics differ", lambda: run(policy, admissions, root, wrong_binary))

    missing = copy.deepcopy(record)
    missing["artifacts"].pop()
    expect_failure("inventory is incomplete", lambda: run(policy, admissions, root, missing))

    duplicate = copy.deepcopy(record)
    duplicate["artifacts"][-1]["harness"] = duplicate["artifacts"][0]["harness"]
    expect_failure("duplicated or unknown", lambda: run(policy, admissions, root, duplicate))

    escape = copy.deepcopy(record)
    escape["artifacts"][0]["path"] = "../outside"
    expect_failure("escapes", lambda: run(policy, admissions, root, escape))

    nested = copy.deepcopy(record)
    nested["artifacts"][0]["path"] = "raw/subdirectory/file"
    expect_failure("escapes", lambda: run(policy, admissions, root, nested))

    qemu_root = root / "qemu"
    qemu = make_record(policy, admissions, qemu_root, "qemu-aarch64")
    assert run(policy, admissions, qemu_root, qemu)["admission_eligible"] is False
    false_native = copy.deepcopy(qemu)
    false_native["claims"]["native_performance"] = True
    expect_failure("unauthenticated evidence", lambda: run(policy, admissions, qemu_root, false_native))

    qemu_candidate = copy.deepcopy(admissions)
    qemu_backend = next(item for item in qemu_candidate["backends"] if item["id"] == qemu["run"]["backend"])
    qemu_backend["status"] = "candidate"
    false_eligible = copy.deepcopy(qemu)
    false_eligible["claims"]["admission_eligible"] = True
    expect_failure("attestation verifier is unavailable", lambda: run(policy, qemu_candidate, qemu_root, false_eligible))

    operating_cases = (
        ("local-amd-x86_64", "x86-sha", ["meaningless-state"]),
        ("local-amd-x86_64", "x86-avx2", ["x86_64", "avx2-usable-on-current-logical-cpu"]),
        ("local-amd-x86_64", "x86-avx512", ["osxsave-disabled", "xcr0-zmm-disabled"]),
        ("riscv64-cloud", "riscv-vector", ["ratified-vector-isa", "vector-state-disabled"]),
    )
    for lane_id, backend_id, operating_state in operating_cases:
        state_root = root / f"state-{backend_id}"
        state_record = make_record(policy, admissions, state_root, lane_id, backend_id)
        state_record["cpu"]["operating_state"] = operating_state
        state_record["cpu"]["logical_cpu_identity_sha256"] = schema.cpu_identity_digest(state_record["cpu"])
        expect_failure("required ABI or vector operating state", lambda value=state_record, path=state_root: run(policy, admissions, path, value))
