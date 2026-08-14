#!/usr/bin/env python3
"""Positive and broken-fixture tests for v0.22.2 CPU evidence admission."""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

import cpu_evidence_fixture_tests as fixtures
import cpu_evidence_policy as evidence
import cpu_evidence_schema as schema


def expect_failure(message: str, callback) -> None:
    try:
        callback()
    except schema.CpuEvidenceError as error:
        if message not in str(error):
            raise AssertionError(f"expected {message!r}, received {error!s}") from error
    else:
        raise AssertionError(f"expected CPU policy rejection: {message}")


def main() -> int:
    policy, admissions = evidence.load_and_validate()
    first = evidence.json_bytes(evidence.build_ledger(policy, admissions))
    second = evidence.json_bytes(evidence.build_ledger(policy, admissions))
    assert first == second
    assert evidence.validate_all_records(policy, admissions) == []

    weakened = copy.deepcopy(policy)
    weakened["admission"]["scalar_build_independent"] = False
    expect_failure("admission semantics", lambda: schema.validate_policy(weakened))

    qemu = copy.deepcopy(policy)
    lane = next(item for item in qemu["lanes"] if item["id"] == "qemu-aarch64")
    lane["status"] = "registered-unmeasured"
    expect_failure("emulated lane gained", lambda: schema.validate_policy(qemu))

    noisy = copy.deepcopy(policy)
    noisy["limits"]["maximum_coefficient_of_variation_ppm"] = 1_000_000
    expect_failure("limits drifted", lambda: schema.validate_policy(noisy))

    incomplete = copy.deepcopy(admissions)
    incomplete["backends"].pop()
    boundary = evidence.read(evidence.BOUNDARY)
    expect_failure(
        "inventory is incomplete",
        lambda: evidence.validate_admissions(policy, incomplete, boundary),
    )

    admitted = copy.deepcopy(admissions)
    admitted["backends"][0]["status"] = "admitted"
    expect_failure(
        "unsupported admission claim",
        lambda: evidence.validate_admissions(policy, admitted, boundary),
    )

    emulated_lane = copy.deepcopy(admissions)
    emulated_lane["backends"][0]["native_lanes"] = ["qemu-x86_64"]
    expect_failure(
        "invalid native lane",
        lambda: evidence.validate_admissions(policy, emulated_lane, boundary),
    )

    weakened_state = copy.deepcopy(admissions)
    weakened_state["backends"][2]["required_operating_state"] = [
        "x86_64",
        "avx2-usable-on-current-logical-cpu",
    ]
    expect_failure(
        "operating-state requirements drifted",
        lambda: evidence.validate_admissions(policy, weakened_state, boundary),
    )

    attributes = evidence.ATTRIBUTES.read_text(encoding="utf-8")
    broken_attributes = attributes.replace("* text=auto eol=lf\n", "")
    original_attributes = evidence.ATTRIBUTES
    with tempfile.TemporaryDirectory(prefix="brynja-cpu-attributes-") as temporary:
        fixture = Path(temporary) / ".gitattributes"
        fixture.write_text(broken_attributes, encoding="utf-8")
        evidence.ATTRIBUTES = fixture
        try:
            expect_failure(
                "LF checkout policy drifted",
                evidence.validate_repository_binding,
            )
        finally:
            evidence.ATTRIBUTES = original_attributes

    with tempfile.TemporaryDirectory(prefix="brynja-cpu-evidence-") as temporary:
        fixtures.test(policy, admissions, Path(temporary))

    original_root = evidence.EVIDENCE_ROOT
    with tempfile.TemporaryDirectory(prefix="brynja-cpu-inventory-") as temporary:
        evidence.EVIDENCE_ROOT = Path(temporary)
        try:
            for index in range(policy["limits"]["maximum_evidence_manifests"] + 1):
                run = evidence.EVIDENCE_ROOT / f"run-{index:03d}"
                run.mkdir()
                (run / "manifest.toml").write_text("", encoding="utf-8")
            expect_failure(
                "manifest inventory exceeds its bound",
                lambda: evidence.evidence_manifests(
                    policy["limits"]["maximum_evidence_manifests"]
                ),
            )
        finally:
            evidence.EVIDENCE_ROOT = original_root

    print("CPU evidence rejects 55 authentication, checkout, parser, semantics, operating-state, correctness, resource, and admission regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
