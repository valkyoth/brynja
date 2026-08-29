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


def inputs(register: dict | None = None) -> tuple:
    ledger = lib.read_json(standards.LEDGER)
    modified_register = register is not None
    register = register or lib.read_json(surfaces.REGISTER)
    versions = checker.roadmap_versions()
    if modified_register:
        matrix = lib.read_json(lib.MATRIX)["requirements"]
        foundation_ids = {
            item["id"] for item in lib.read_json(lib.POLICY)["requirements"]
        }
        foundation = [
            item for item in matrix if item["id"] in foundation_ids
        ]
        existing = [
            item
            for item in matrix
            if item.get("profile") != "optional-legacy-residual"
        ]
        return (
            ledger,
            register,
            versions,
            foundation,
            lib.read_json(lib.DOMAIN_COVERAGE),
            lib.read_json(lib.TRANSPORT_COVERAGE),
            existing,
        )
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


def residual_build(
    policy: dict | None = None,
    register: dict | None = None,
    section_policy: dict | None = None,
) -> tuple:
    return residual.build(
        *inputs(register),
        policy=policy,
        section_policy=section_policy,
    )


def closure_build(
    claims: dict | None = None,
    matrix: dict | None = None,
) -> dict:
    foundation_ids = {
        item["id"] for item in lib.read_json(lib.POLICY)["requirements"]
    }
    return closure.build(
        lib.read_json(standards.LEDGER),
        lib.read_json(surfaces.REGISTER),
        matrix or lib.read_json(lib.MATRIX),
        lib.read_json(lib.DOMAIN_COVERAGE),
        lib.read_json(lib.TRANSPORT_COVERAGE),
        lib.read_json(lib.RESIDUAL_COVERAGE),
        foundation_ids,
        claims=claims,
    )


def test_current_residual_repository() -> None:
    requirements, coverage, _digest = residual_build()
    assert len(requirements) == 51
    assert coverage["authority_count"] == 33
    assert coverage["normative_section_count"] == 182
    assert coverage["mapped_normative_section_count"] == 165
    assert coverage["surface_count"] == 792
    requirement_map = {item["id"]: item for item in requirements}
    assert all(
        item["id"] in requirement_map[item["requirement_id"]]["decision_ids"]
        for item in coverage["surfaces"]
    )
    assert standards.json_bytes(coverage) == lib.RESIDUAL_COVERAGE.read_bytes()


def test_current_bidirectional_closure() -> None:
    artifact = closure_build()
    assert len(artifact["sources"]) == 130
    assert len(artifact["plans"]) == 510
    assert len(artifact["surfaces"]) == 4456
    assert len(artifact["requirements"]) == 169
    assert len(artifact["local_rights"]) == 18
    assert len(artifact["mutable_authorities"]) == 15
    assert len(artifact["blockers"]) == 3
    assert standards.json_bytes(artifact) == lib.CLOSURE.read_bytes()


def test_missing_surface_group_fails() -> None:
    broken = copy.deepcopy(residual.read_policy())
    broken["surface_group"].pop()
    assert_fails("residual surface identities differ", residual_build, broken)


def test_duplicate_surface_group_fails() -> None:
    broken = copy.deepcopy(residual.read_policy())
    broken["surface_group"].append(copy.deepcopy(broken["surface_group"][0]))
    assert_fails("duplicate or malformed stable IDs", residual_build, broken)


def test_repeated_explicit_surface_fails() -> None:
    broken = copy.deepcopy(residual.read_policy())
    broken["surface_group"][0]["surface_ids"].append(
        broken["surface_group"][0]["surface_ids"][0]
    )
    assert_fails("malformed surface group", residual_build, broken)


def mutated_nonrepresentative(field: str, value) -> tuple[dict, dict]:
    register = copy.deepcopy(lib.read_json(surfaces.REGISTER))
    policy = copy.deepcopy(residual.read_policy())
    group = next(
        item
        for item in policy["surface_group"]
        if item["id"] == "BRY-REQ-APPLICATION-0130"
    )
    target_id = group["surface_ids"][1]
    target = next(item for item in register["surfaces"] if item["id"] == target_id)
    target[field] = value
    policy["surface_register_sha256"] = standards.sha256(
        standards.json_bytes(register)
    )
    return register, policy


def test_nonrepresentative_source_drift_fails() -> None:
    register, policy = mutated_nonrepresentative(
        "normative_sources", ["rfc:9954"]
    )
    assert_fails("unrelated surfaces", residual_build, policy, register)


def test_nonrepresentative_code_target_drift_fails() -> None:
    register, policy = mutated_nonrepresentative(
        "code_target", "crates/brynja-tls/src/other.rs"
    )
    assert_fails(
        "one implementation and test boundary",
        residual_build,
        policy,
        register,
    )


def test_nonrepresentative_test_target_drift_fails() -> None:
    register, policy = mutated_nonrepresentative(
        "test_target", "tests/surface/alpn.rs#other"
    )
    assert_fails(
        "one implementation and test boundary",
        residual_build,
        policy,
        register,
    )


def test_nonrepresentative_owner_drift_fails() -> None:
    register, policy = mutated_nonrepresentative("owner", "0.131.0")
    assert_fails(
        "contains incompatible surfaces", residual_build, policy, register
    )


def test_nonrepresentative_disposition_drift_fails() -> None:
    register, policy = mutated_nonrepresentative(
        "disposition", "future-work"
    )
    assert_fails(
        "contains incompatible surfaces", residual_build, policy, register
    )


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


def test_missing_residual_section_binding_fails() -> None:
    broken = copy.deepcopy(
        residual.sections.read_policy(residual.SECTION_POLICY)
    )
    broken["binding"] = [
        item
        for item in broken["binding"]
        if not (
            item["requirement_id"] == "BRY-REQ-ECH-0142"
            and item["source_id"] == "rfc:9180"
        )
    ]
    assert_fails(
        "normative requirement/source binding set differs",
        residual_build,
        None,
        None,
        broken,
    )


def test_missing_residual_section_exclusion_fails() -> None:
    broken = copy.deepcopy(
        residual.sections.read_policy(residual.SECTION_POLICY)
    )
    broken["exclusion"].pop()
    assert_fails(
        "unmapped normative sections",
        residual_build,
        None,
        None,
        broken,
    )


def test_premature_owner_fails() -> None:
    broken = copy.deepcopy(residual.read_policy())
    broken["surface_group"][0]["owner"] = "1.0.0"
    assert_fails("contains incompatible surfaces", residual_build, broken)


def test_missing_rights_record_fails() -> None:
    broken = copy.deepcopy(closure.read_claims())
    broken["local_right"].pop()
    assert_fails("rights coverage is incomplete", closure_build, broken)


def test_stale_mutable_guidance_fails() -> None:
    broken = copy.deepcopy(closure.read_claims())
    broken["mutable_authority"][0]["status"] = "current"
    assert_fails("invalid mutable authority record", closure_build, broken)


def test_missing_hybrid_resolution_record_fails() -> None:
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


def test_source_blocked_requirement_cannot_be_actionable() -> None:
    broken = copy.deepcopy(lib.read_json(lib.MATRIX))
    target = next(
        item
        for item in broken["requirements"]
        if item["id"] == "BRY-REQ-LEGACY-0500"
    )
    target["lifecycle"] = "legacy"
    assert_fails(
        "must remain source blocked",
        closure_build,
        None,
        broken,
    )


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
