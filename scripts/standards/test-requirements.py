#!/usr/bin/env python3
"""Positive and broken-fixture tests for normative requirement evidence."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import requirements_lib as lib  # noqa: E402
import requirements_test_support as support  # noqa: E402
import standards_lib as standards  # noqa: E402

assert_fails = support.assert_fails
bind = support.bind
checker = support.checker
inputs = support.inputs
requirement = support.requirement


def test_current_repository() -> None:
    matrix, indexes = checker.build_matrix()
    assert len(matrix["requirements"]) == 169
    assert {item["lifecycle"] for item in matrix["requirements"]} == lib.LIFECYCLES
    assert standards.json_bytes(matrix) == lib.MATRIX.read_bytes()
    assert standards.json_bytes(indexes) == lib.INDEXES.read_bytes()
    assert standards.json_bytes(lib.schema_document()) == lib.SCHEMA.read_bytes()
    assert lib.render_coverage(matrix, indexes) == lib.COVERAGE.read_bytes()
    assert lib.DOMAIN_COVERAGE.is_file()
    assert lib.TRANSPORT_COVERAGE.is_file()
    assert lib.RESIDUAL_COVERAGE.is_file()
    assert lib.CLOSURE.is_file()


def test_coverage_dispositions_are_declared_by_schema() -> None:
    allowed = set(lib.schema_document()["section_dispositions"])
    for path in (
        lib.DOMAIN_COVERAGE,
        lib.TRANSPORT_COVERAGE,
        lib.RESIDUAL_COVERAGE,
    ):
        coverage = lib.read_json(path)
        observed = {
            section["disposition"]
            for source in coverage["authorities"]
            for section in source.get("normative_sections", [])
            if "disposition" in section
        }
        assert observed <= allowed


def test_generation_is_deterministic() -> None:
    first = checker.build_matrix()
    second = checker.build_matrix()
    assert standards.json_bytes(first) == standards.json_bytes(second)


def test_stable_id_survives_rendering() -> None:
    policy, ledger, register = inputs()
    original, _ = checker.build_matrix(
        policy, ledger, register, previous=False
    )
    changed = copy.deepcopy(policy)
    changed["requirements"][0]["statement"] += " Rendering changed."
    updated, _ = checker.build_matrix(
        changed, ledger, register, previous=False
    )
    assert [item["id"] for item in original["requirements"]] == [
        item["id"] for item in updated["requirements"]
    ]
    assert standards.json_bytes(original) != standards.json_bytes(updated)


def test_lowercase_normative_word_does_not_satisfy_strength() -> None:
    candidate = {
        "decision": "enforce",
        "deviation_rationale": None,
        "id": "BRY-REQ-TEST-0001",
        "strength": "MUST",
    }
    assert_fails(
        "strength is absent",
        checker.validate_strength,
        candidate,
        "an implementation must reject this lowercase-only fixture",
    )


def test_missing_residual_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    broken["requirements"][0]["residual"] = ""
    assert_fails(
        "requires residual context",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_iana_source_drift_changes_matrix() -> None:
    policy, ledger, register = inputs()
    original, _ = checker.build_matrix(
        policy, ledger, register, previous=False
    )
    changed_register = copy.deepcopy(register)
    target = next(
        item
        for item in changed_register["surfaces"]
        if item["id"]
        == "iana.tls-parameters.tls-parameters-4.tls-aes-128-gcm-sha256.1"
    )
    target["record"]["fields"]["rec"] = "MUTATED"
    changed_policy = copy.deepcopy(policy)
    bind(changed_policy, ledger, changed_register)
    updated, _ = checker.build_matrix(
        changed_policy,
        ledger,
        changed_register,
        previous=False,
    )
    original_source = next(
        item
        for item in original["requirements"]
        if item["id"] == "BRY-REQ-TLS-0001"
    )["source"]
    updated_source = next(
        item
        for item in updated["requirements"]
        if item["id"] == "BRY-REQ-TLS-0001"
    )["source"]
    assert original_source["record_sha256"] != updated_source["record_sha256"]


def test_source_ledger_hash_drift_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(ledger)
    broken["rfcs"][0]["sha256"] = "0" * 64
    assert_fails(
        "not bound to the current source ledger",
        checker.build_matrix,
        policy,
        broken,
        register,
    )


def test_surface_register_hash_drift_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(register)
    broken["surfaces"][0]["disposition"] = "implemented"
    assert_fails(
        "not bound to the current surface register",
        checker.build_matrix,
        policy,
        ledger,
        broken,
    )


def test_rfc_status_drift_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(ledger)
    source = next(item for item in broken["rfcs"] if item["number"] == 8174)
    source["status"] = "MUTATED"
    assert_fails(
        "not bound to the current source ledger",
        checker.build_matrix,
        policy,
        broken,
        register,
    )


def test_errata_drift_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(ledger)
    source = next(item for item in broken["rfcs"] if item["number"] == 2119)
    source["errata"].pop()
    assert_fails(
        "not bound to the current source ledger",
        checker.build_matrix,
        policy,
        broken,
        register,
    )


def test_absent_rfc_section_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    requirement(broken, "BRY-REQ-STD-0001")["source"]["section"] = "999"
    assert_fails(
        "references absent RFC section",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_absent_extraction_anchor_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    requirement(broken, "BRY-REQ-STD-0001")["source"]["anchor"] = "not present"
    assert_fails(
        "extraction anchor is absent",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_unknown_iana_surface_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    requirement(broken, "BRY-REQ-TLS-0001")["source"][
        "surface_id"
    ] = "iana.unknown"
    assert_fails(
        "references unknown IANA surface",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def main() -> int:
    count = support.run_tests(globals())
    print(f"{count} normative-requirement core tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
