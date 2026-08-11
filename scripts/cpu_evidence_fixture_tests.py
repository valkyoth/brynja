#!/usr/bin/env python3
"""Adversarial fixtures for the v0.13.3 CPU evidence schema."""

from __future__ import annotations

import copy
import hashlib
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


def make_record(policy: dict, admissions: dict, root: Path, lane_id: str = "local-amd-x86_64") -> dict:
    lanes = schema.lane_map(policy)
    lane = lanes[lane_id]
    backend = next(
        item for item in admissions["backends"]
        if item["architecture"] == lane["architecture"]
    )
    artifacts = []
    raw = root / "raw"
    raw.mkdir(parents=True)
    for harness in policy["harnesses"]:
        name = f"{harness['id']}.txt"
        data = f"{harness['id']}: fixture pass\n".encode()
        (raw / name).write_bytes(data)
        artifacts.append({
            "harness": harness["id"],
            "path": f"raw/{name}",
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        })
    native = lane["execution_kind"] == "native"
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
            "operating_state": ["fixture-state-observed"],
        },
        "environment": {
            "os": lane["os"], "kernel": "fixture-kernel", "virtualization": "none",
            "compiler": "rustc 1.97.1", "compiler_commit": COMMIT,
            "target": f"{lane['architecture']}-fixture", "rustflags": ["-Copt-level=3"],
            "frequency_policy": "fixed-and-recorded", "clock_source": "monotonic-fixture",
            "isolation": "dedicated-fixture",
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
        "artifacts": artifacts,
        "claims": {
            "native_performance": native, "native_side_channel": native,
            "admission_eligible": False,
            "residual_gaps": ["statistical-testing-is-not-proof"],
        },
    }
    record["cpu"]["logical_cpu_identity_sha256"] = schema.cpu_identity_digest(record["cpu"])
    return record


def run(policy: dict, admissions: dict, root: Path, record: dict) -> dict:
    return schema.validate_record(record, policy, admissions, root, EVALUATED)


def test(policy: dict, admissions: dict, root: Path) -> None:
    record = make_record(policy, admissions, root)
    assert run(policy, admissions, root, record)["admission_eligible"] is False

    candidate = copy.deepcopy(admissions)
    target = next(item for item in candidate["backends"] if item["id"] == record["run"]["backend"])
    target["status"] = "candidate"
    eligible = copy.deepcopy(record)
    eligible["claims"]["admission_eligible"] = True
    assert run(policy, candidate, root, eligible)["admission_eligible"] is True

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
    expect_failure("native performance", lambda: run(policy, admissions, qemu_root, false_native))

    qemu_candidate = copy.deepcopy(admissions)
    qemu_backend = next(item for item in qemu_candidate["backends"] if item["id"] == qemu["run"]["backend"])
    qemu_backend["status"] = "candidate"
    false_eligible = copy.deepcopy(qemu)
    false_eligible["claims"]["admission_eligible"] = True
    expect_failure("admission claim differs", lambda: run(policy, qemu_candidate, qemu_root, false_eligible))
