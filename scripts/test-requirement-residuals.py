#!/usr/bin/env python3
"""Positive and broken fixtures for v0.3.5 residual closure."""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import requirements_closure as closure  # noqa: E402
import requirements_domain as domain  # noqa: E402
import requirements_lib as lib  # noqa: E402
import requirements_residual as residual  # noqa: E402
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


def inputs() -> tuple:
    ledger = lib.read_json(standards.LEDGER)
    register = lib.read_json(surfaces.REGISTER)
    versions = checker.roadmap_versions()
    foundation_matrix, _indexes = checker.build_matrix(
        previous=False, include_domains=False
    )
    foundation = foundation_matrix["requirements"]
    domain_requirements, domain_coverage, _digest = domain.build(
        ledger, register, versions
    )
    transport_requirements, transport_coverage, _digest = transport.build(
        ledger, register, versions
    )
    existing = foundation + domain_requirements + transport_requirements
    return (
        ledger,
        register,
        versions,
        foundation,
        domain_coverage,
        transport_coverage,
        existing,
    )


def residual_build(policy: dict | None = None) -> tuple:
    return residual.build(*inputs(), policy=policy)


def closure_build(claims: dict | None = None) -> dict:
    foundation_ids = {
        item["id"] for item in lib.read_json(lib.POLICY)["requirements"]
    }
    return closure.build(
        lib.read_json(standards.LEDGER),
        lib.read_json(surfaces.REGISTER),
        lib.read_json(lib.MATRIX),
        lib.read_json(lib.DOMAIN_COVERAGE),
        lib.read_json(lib.TRANSPORT_COVERAGE),
        lib.read_json(lib.RESIDUAL_COVERAGE),
        foundation_ids,
        claims=claims,
    )


def test_current_residual_repository() -> None:
    requirements, coverage, _digest = residual_build()
    assert len(requirements) == 38
    assert coverage["authority_count"] == 33
    assert coverage["normative_section_count"] == 182
    assert coverage["surface_count"] == 741
    assert standards.json_bytes(coverage) == lib.RESIDUAL_COVERAGE.read_bytes()


def test_current_bidirectional_closure() -> None:
    artifact = closure_build()
    assert len(artifact["sources"]) == 126
    assert len(artifact["plans"]) == 205
    assert len(artifact["surfaces"]) == 4422
    assert len(artifact["requirements"]) == 154
    assert len(artifact["local_rights"]) == 15
    assert len(artifact["mutable_authorities"]) == 13
    assert len(artifact["blockers"]) == 3
    assert standards.json_bytes(artifact) == lib.CLOSURE.read_bytes()


def test_missing_surface_group_fails() -> None:
    broken = copy.deepcopy(residual.read_policy())
    broken["surface_group"].pop()
    assert_fails("residual surface groups differ", residual_build, broken)


def test_duplicate_surface_group_fails() -> None:
    broken = copy.deepcopy(residual.read_policy())
    broken["surface_group"].append(copy.deepcopy(broken["surface_group"][0]))
    assert_fails("duplicate or malformed stable IDs", residual_build, broken)


def test_orphan_source_fails() -> None:
    broken = copy.deepcopy(residual.read_policy())
    target = next(
        item for item in broken["surface_group"] if item["id"] == "BRY-REQ-PQ-0117"
    )
    target["sources"] = ["rfc:9954"]
    assert_fails("source-to-requirement closure", residual_build, broken)


def test_draft_identifier_fails() -> None:
    broken = copy.deepcopy(residual.read_policy())
    broken["surface_group"][0]["sources"] = ["draft:unpublished"]
    assert_fails("unknown authority", residual_build, broken)


def test_premature_owner_fails() -> None:
    broken = copy.deepcopy(residual.read_policy())
    broken["surface_group"][0]["owner"] = "1.0.0"
    assert_fails("residual surface groups differ", residual_build, broken)


def test_missing_rights_record_fails() -> None:
    broken = copy.deepcopy(closure.read_claims())
    broken["local_right"].pop()
    assert_fails("rights coverage is incomplete", closure_build, broken)


def test_stale_mutable_guidance_fails() -> None:
    broken = copy.deepcopy(closure.read_claims())
    broken["mutable_authority"][0]["status"] = "current"
    assert_fails("invalid mutable authority record", closure_build, broken)


def test_missing_hybrid_blocker_fails() -> None:
    broken = copy.deepcopy(closure.read_claims())
    broken["blocker"] = [
        item
        for item in broken["blocker"]
        if item["id"] != "ecdhe-ml-kem-groups"
    ]
    assert_fails("blocker set is incomplete", closure_build, broken)


def test_missing_legacy_exclusion_fails() -> None:
    broken = copy.deepcopy(closure.read_claims())
    target = next(
        item
        for item in broken["blocker"]
        if item["id"] == "legacy-non-rfc-sources"
    )
    target["surfaces"].pop()
    assert_fails("legacy source-rights blocker", closure_build, broken)


def test_orphan_plan_fails() -> None:
    broken = copy.deepcopy(closure.read_claims())
    target = next(
        item
        for item in broken["plan_boundary"]
        if "0.1.0" in item["versions"]
    )
    target["versions"].remove("0.1.0")
    assert_fails("plan-to-source boundary differs", closure_build, broken)


def test_unbound_fips_plan_fails() -> None:
    broken = copy.deepcopy(closure.read_claims())
    target = next(
        item
        for item in broken["plan_boundary"]
        if item["class"] == "authority-blocked"
    )
    target["blocker"] = "unknown"
    assert_fails("unknown blocker", closure_build, broken)


def main() -> int:
    count = support.run_tests(globals())
    print(f"{count} residual-closure tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
