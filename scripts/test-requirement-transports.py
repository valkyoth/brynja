#!/usr/bin/env python3
"""Positive and broken fixtures for v0.3.4 transport requirements."""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import requirements_bundle as bundle  # noqa: E402
import requirements_lib as lib  # noqa: E402
import requirements_test_support as support  # noqa: E402
import requirements_transport as transport  # noqa: E402
import standards_lib as standards  # noqa: E402
import surface_lib as surfaces  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "check_requirements",
    Path(__file__).with_name("check-requirements.py"),
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load requirement checker")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
assert_fails = support.assert_fails


def inputs() -> tuple[dict, dict, set[str]]:
    return (
        lib.read_json(standards.LEDGER),
        lib.read_json(surfaces.REGISTER),
        checker.roadmap_versions(),
    )


def test_current_repository() -> None:
    ledger, register, versions = inputs()
    requirements, coverage, _digest = transport.build(
        ledger, register, versions
    )
    assert len(requirements) == 70
    assert coverage["authority_count"] == 40
    assert coverage["deferred_authority_count"] == 1
    assert coverage["mapped_normative_section_count"] == 539
    assert coverage["excluded_normative_section_count"] == 11
    assert coverage["owner_milestone_count"] == 63
    assert coverage["surface_count"] == 483
    assert standards.json_bytes(coverage) == lib.TRANSPORT_COVERAGE.read_bytes()


def test_generation_is_deterministic() -> None:
    ledger, register, versions = inputs()
    first = transport.build(ledger, register, versions)
    second = transport.build(ledger, register, versions)
    assert standards.json_bytes(first) == standards.json_bytes(second)


def test_every_transport_milestone_has_one_semantic_requirement() -> None:
    ledger, register, versions = inputs()
    requirements, coverage, _digest = transport.build(
        ledger, register, versions
    )
    requirement_ids = {item["id"] for item in requirements}
    semantic = [
        item
        for item in register["surfaces"]
        if "requirement_id" in item
    ]
    assert len(semantic) == 63
    assert {item["requirement_id"] for item in semantic} <= requirement_ids
    assert {item["owner"] for item in semantic} == set(
        coverage["owner_milestones"]
    )


def test_all_authorities_are_covered_or_explicitly_deferred() -> None:
    ledger, register, versions = inputs()
    requirements, coverage, _digest = transport.build(
        ledger, register, versions
    )
    cited = {
        source["id"]
        for requirement in requirements
        for source in requirement["sources"]
    }
    covered = {item["id"] for item in coverage["authorities"]}
    deferred = {item["id"] for item in coverage["authority_deferrals"]}
    assert cited == covered
    assert deferred == {"rfc:9850"}
    assert cited.isdisjoint(deferred)


def test_scope_binding_drift_fails() -> None:
    ledger, register, _versions = inputs()
    scope, _requirements, _digest = transport.load_policy(ledger)
    broken = copy.deepcopy(scope)
    broken["surface_register_sha256"] = "0" * 64
    assert_fails(
        "not bound to the current surface register",
        bundle.validate_scope,
        transport.CONFIG,
        broken,
        ledger,
        register,
    )


def test_missing_owner_milestone_fails() -> None:
    ledger, register, versions = inputs()
    scope, requirements, digest = transport.load_policy(ledger)
    broken = copy.deepcopy(scope)
    broken["owner_milestones"].pop()
    assert_fails(
        "owner-milestone coverage is incomplete",
        bundle.build,
        transport.CONFIG,
        ledger,
        register,
        versions,
        (broken, requirements, digest),
    )


def test_authority_role_swap_fails() -> None:
    ledger, register, versions = inputs()
    scope, requirements, digest = transport.load_policy(ledger)
    broken = copy.deepcopy(requirements)
    broken[0]["sources"][0]["authority_role"] = "evidence"
    assert_fails(
        "misclassifies authority role",
        bundle.build,
        transport.CONFIG,
        ledger,
        register,
        versions,
        (scope, broken, digest),
    )


def test_duplicate_stable_id_fails() -> None:
    ledger, register, versions = inputs()
    scope, requirements, digest = transport.load_policy(ledger)
    broken = copy.deepcopy(requirements)
    broken[1]["id"] = broken[0]["id"]
    assert_fails(
        "duplicate stable IDs",
        bundle.build,
        transport.CONFIG,
        ledger,
        register,
        versions,
        (scope, broken, digest),
    )


def main() -> int:
    count = support.run_tests(globals())
    print(f"{count} transport-requirement tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
