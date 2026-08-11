#!/usr/bin/env python3
"""Positive and broken fixtures for v0.3.3 domain requirement coverage."""

from __future__ import annotations

import copy
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import requirements_domain as domain  # noqa: E402
import requirements_domain_coverage as coverage_lib  # noqa: E402
import requirements_lib as lib  # noqa: E402
import requirements_test_support as support  # noqa: E402
import standards_lib as standards  # noqa: E402
import surface_lib as surfaces  # noqa: E402

assert_fails = support.assert_fails
checker = support.checker


def inputs() -> tuple[dict, dict, set[str]]:
    return (
        lib.read_json(standards.LEDGER),
        lib.read_json(surfaces.REGISTER),
        checker.roadmap_versions(),
    )


def validation_fixture() -> tuple[dict, dict, set[str], dict, dict, set[str]]:
    ledger, register, versions = inputs()
    _scope, requirements, _digest = domain.load_policy()
    authorities = domain.expected_authorities(ledger)
    surface_map = {item["id"]: item for item in register["surfaces"]}
    allowed = {
        item["id"]
        for item in register["surfaces"]
        if item["domain"] in domain.SURFACE_DOMAINS
        or set(item["normative_sources"]).intersection(authorities)
    }
    return requirements[0], authorities, versions, surface_map, register, allowed


def test_current_repository() -> None:
    ledger, register, versions = inputs()
    requirements, coverage, _digest = domain.build(ledger, register, versions)
    assert len(requirements) == 34
    assert coverage["authority_count"] == 53
    assert coverage["mapped_normative_section_count"] == 352
    assert coverage["excluded_normative_section_count"] == 12
    assert coverage["normative_section_count"] == 364
    assert coverage["surface_count"] == 3323
    assert standards.json_bytes(coverage) == lib.DOMAIN_COVERAGE.read_bytes()


def test_generation_is_deterministic() -> None:
    ledger, register, versions = inputs()
    first = domain.build(ledger, register, versions)
    second = domain.build(ledger, register, versions)
    assert standards.json_bytes(first) == standards.json_bytes(second)


def test_every_authority_is_covered_once_or_more() -> None:
    ledger, register, versions = inputs()
    requirements, coverage, _digest = domain.build(ledger, register, versions)
    cited = {
        source["id"]
        for requirement in requirements
        for source in requirement["sources"]
    }
    assert cited == {item["id"] for item in coverage["authorities"]}
    roles = {item["authority_role"] for item in coverage["authorities"]}
    assert roles == domain.AUTHORITY_ROLES


def test_every_selected_surface_is_assigned_or_deferred() -> None:
    ledger, register, versions = inputs()
    _requirements, coverage, _digest = domain.build(
        ledger, register, versions
    )
    assert {item["coverage"] for item in coverage["surfaces"]} == {
        "deferred",
        "requirement",
    }
    assert sum(
        item["coverage"] == "deferred" for item in coverage["surfaces"]
    ) == 2


def test_normative_sections_bind_exact_text() -> None:
    ledger, _register, _versions = inputs()
    entry = next(item for item in ledger["rfcs"] if item["number"] == 5280)
    sections = coverage_lib.normative_sections(entry)
    assert sections
    assert all(item["occurrences"] for item in sections)
    assert all(len(item["section_sha256"]) == 64 for item in sections)


def test_source_ledger_binding_drift_fails() -> None:
    ledger, register, _versions = inputs()
    scope, _requirements, _digest = domain.load_policy()
    broken = copy.deepcopy(ledger)
    broken["rfcs"][0]["sha256"] = "0" * 64
    assert_fails(
        "not bound to the current source ledger",
        domain.validate_scope,
        scope,
        broken,
        register,
    )


def test_surface_register_binding_drift_fails() -> None:
    ledger, register, _versions = inputs()
    scope, _requirements, _digest = domain.load_policy()
    broken = copy.deepcopy(register)
    broken["surfaces"][0]["owner"] = "0.0.0"
    assert_fails(
        "not bound to the current surface register",
        domain.validate_scope,
        scope,
        ledger,
        broken,
    )


def test_authority_role_misclassification_fails() -> None:
    item, authorities, versions, surface_map, _register, allowed = (
        validation_fixture()
    )
    broken = copy.deepcopy(item)
    broken["sources"][0]["authority_role"] = "evidence"
    assert_fails(
        "misclassifies authority role",
        domain.validate_requirement,
        broken,
        versions,
        authorities,
        surface_map,
        allowed,
    )


def test_positive_and_negative_tests_are_required() -> None:
    item, authorities, versions, surface_map, _register, allowed = (
        validation_fixture()
    )
    broken = copy.deepcopy(item)
    broken["tests"] = broken["tests"][:1]
    assert_fails(
        "requires positive and negative tests",
        domain.validate_requirement,
        broken,
        versions,
        authorities,
        surface_map,
        allowed,
    )


def test_work_bound_is_substantive() -> None:
    item, authorities, versions, surface_map, _register, allowed = (
        validation_fixture()
    )
    broken = copy.deepcopy(item)
    broken["work_bound"] = "short"
    assert_fails(
        "requires substantive work_bound",
        domain.validate_requirement,
        broken,
        versions,
        authorities,
        surface_map,
        allowed,
    )


def test_resource_or_work_invariant_is_required() -> None:
    item, authorities, versions, surface_map, _register, allowed = (
        validation_fixture()
    )
    broken = copy.deepcopy(item)
    broken["invariants"] = ["constant-time", "side-channel"]
    assert_fails(
        "incomplete assurance invariants",
        domain.validate_requirement,
        broken,
        versions,
        authorities,
        surface_map,
        allowed,
    )


def test_unknown_owner_fails() -> None:
    item, authorities, versions, surface_map, _register, allowed = (
        validation_fixture()
    )
    broken = copy.deepcopy(item)
    broken["owner"] = "999.0.0"
    assert_fails(
        "absent or unknown owner",
        domain.validate_requirement,
        broken,
        versions,
        authorities,
        surface_map,
        allowed,
    )


def test_out_of_scope_decision_fails() -> None:
    item, authorities, versions, surface_map, _register, allowed = (
        validation_fixture()
    )
    broken = copy.deepcopy(item)
    broken["decision_ids"] = ["facility.heartbeat"]
    assert_fails(
        "outside v0.3.3 scope",
        domain.validate_requirement,
        broken,
        versions,
        authorities,
        surface_map,
        allowed,
    )


def test_missing_surface_group_fails() -> None:
    ledger, register, versions = inputs()
    scope, requirements, _digest = domain.load_policy()
    resolved, _coverage, _digest = domain.build(ledger, register, versions)
    broken = copy.deepcopy(scope)
    broken["surface_group"].pop()
    requirement_map = {item["id"]: item for item in resolved}
    assert_fails(
        "uncovered domain surface",
        coverage_lib.surface_assignments,
        broken,
        register,
        requirement_map,
        domain.SURFACE_DOMAINS,
    )


def test_duplicate_surface_group_fails() -> None:
    ledger, register, versions = inputs()
    scope, _requirements, _digest = domain.load_policy()
    resolved, _coverage, _digest = domain.build(ledger, register, versions)
    broken = copy.deepcopy(scope)
    broken["surface_group"].append(copy.deepcopy(broken["surface_group"][0]))
    requirement_map = {item["id"]: item for item in resolved}
    assert_fails(
        "duplicate surface group",
        coverage_lib.surface_assignments,
        broken,
        register,
        requirement_map,
        domain.SURFACE_DOMAINS,
    )


def test_every_link_requires_authority_and_owner_consistency() -> None:
    requirement, authorities, versions, surface_map, _register, allowed = (
        validation_fixture()
    )
    broken = copy.deepcopy(requirement)
    broken["decision_ids"].append("algorithm.aes")
    broken["mapping_rationale"] += " cross-domain"
    assert_fails(
        "unrelated authorities",
        domain.validate_requirement,
        broken,
        versions,
        authorities,
        surface_map,
        allowed | {"algorithm.aes"},
    )


def main() -> int:
    count = support.run_tests(globals())
    print(f"{count} domain-requirement tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
