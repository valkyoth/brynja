#!/usr/bin/env python3
"""Validate and generate Brynja's normative requirement matrix pilot."""

from __future__ import annotations

import argparse
import re

import requirements_lib as lib
import standards_lib as standards
import surface_lib as surfaces


REQUIREMENT_FIELDS = {
    "applicability",
    "decision",
    "decision_ids",
    "deviation_rationale",
    "evidence",
    "id",
    "lifecycle",
    "owner",
    "residual",
    "revision",
    "scope",
    "source",
    "statement",
    "strength",
    "targets",
    "tests",
}


def roadmap_versions() -> set[str]:
    text = (lib.ROOT / "docs/VERSION_PLAN.md").read_text(encoding="utf-8")
    return set(re.findall(r"`(H?\d+\.\d+(?:\.\d+)?)`", text))


def validate_transition(previous: str, current: str) -> None:
    if previous not in lib.LIFECYCLES or current not in lib.LIFECYCLES:
        lib.fail("requirement transition has unknown lifecycle")
    if current not in lib.TRANSITIONS[previous]:
        lib.fail(f"illegal requirement lifecycle transition: {previous} -> {current}")


def validate_binding(policy: dict, ledger: dict, register: dict) -> None:
    ledger_hash = standards.sha256(standards.json_bytes(ledger))
    register_hash = standards.sha256(standards.json_bytes(register))
    if policy["source_ledger_sha256"] != ledger_hash:
        lib.fail("requirement policy is not bound to the current source ledger")
    if policy["surface_register_sha256"] != register_hash:
        lib.fail("requirement policy is not bound to the current surface register")


def validate_strength(requirement: dict, section_text: str | None) -> None:
    strength = requirement["strength"]
    if strength not in lib.STRENGTHS:
        lib.fail(f"{requirement['id']} has unknown normative strength")
    if section_text is not None and strength not in {"INVARIANT", "REGISTRY"}:
        if strength not in section_text:
            lib.fail(
                f"{requirement['id']} strength is absent from cited RFC section"
            )
    if requirement["decision"] == "deviate":
        if strength not in {"SHOULD", "SHOULD NOT"}:
            lib.fail(f"{requirement['id']} cannot deviate from {strength}")
        rationale = requirement["deviation_rationale"]
        if not isinstance(rationale, str) or len(rationale.strip()) < 40:
            lib.fail(f"{requirement['id']} has a silently weakened SHOULD decision")
    elif requirement["deviation_rationale"] is not None:
        lib.fail(f"{requirement['id']} has an unused deviation rationale")


def resolve_source(
    source: dict,
    requirement_id: str,
    rfcs: dict[str, dict],
    surface_map: dict[str, dict],
) -> tuple[dict, str | None]:
    kind = source.get("kind")
    if kind == "rfc":
        if set(source) != {"anchor", "id", "kind", "section"}:
            lib.fail(f"{requirement_id} has malformed RFC source")
        entry = rfcs.get(source["id"])
        if entry is None:
            lib.fail(f"{requirement_id} references unknown RFC source")
        section = source["section"]
        path = lib.ROOT / "rfc" / f"rfc{entry['number']}.txt"
        sections = lib.rfc_sections(path)
        section_text = sections.get(section)
        if section_text is None:
            lib.fail(f"{requirement_id} references absent RFC section {section}")
        anchor = lib.normalize(source["anchor"])
        if not anchor or len(anchor) > 160 or anchor not in section_text:
            lib.fail(f"{requirement_id} RFC extraction anchor is absent or invalid")
        return (
            {
                "anchor": anchor,
                "errata": entry["errata"],
                "id": source["id"],
                "kind": "rfc",
                "lifecycle": entry["lifecycle"],
                "section": section,
                "section_sha256": lib.section_hash(section_text),
                "sha256": entry["sha256"],
                "status": entry["status"],
            },
            section_text,
        )
    if kind == "iana":
        if set(source) != {"kind", "surface_id"}:
            lib.fail(f"{requirement_id} has malformed IANA source")
        surface = surface_map.get(source["surface_id"])
        if surface is None or surface["kind"] not in {
            "iana-entry",
            "iana-registry",
        }:
            lib.fail(f"{requirement_id} references unknown IANA surface")
        registry = surface["registry"]
        return (
            {
                "collection": registry["collection"],
                "disposition": surface["disposition"],
                "kind": "iana",
                "record_sha256": standards.sha256(
                    standards.json_bytes(surface.get("record", registry))
                ),
                "registry": registry["id"],
                "snapshot_sha256": next(
                    source["sha256"]
                    for source in surface["normative_sources_data"]
                    if source["id"] == f"iana:{registry['collection']}"
                )
                if "normative_sources_data" in surface
                else registry.get("sha256"),
                "surface_id": source["surface_id"],
            },
            None,
        )
    lib.fail(f"{requirement_id} has unknown source kind {kind!r}")


def collection_hashes(ledger: dict) -> dict[str, str]:
    return {entry["id"]: entry["sha256"] for entry in ledger["registries"]}


def validate_targets(requirement: dict) -> None:
    lifecycle = requirement["lifecycle"]
    targets = requirement["targets"]
    if not isinstance(targets, list) or len(targets) != 1:
        lib.fail(f"{requirement['id']} requires exactly one target")
    target = targets[0]
    if set(target) != {"kind", "target"}:
        lib.fail(f"{requirement['id']} has malformed target")
    kind = target["kind"]
    value = target["target"]
    expected_kinds = {
        "blocked": "blocker",
        "caller-owned": "boundary",
        "evidenced": "actual-symbol",
        "implemented": "actual-symbol",
        "legacy": "legacy-boundary",
        "planned": "planned-symbol",
        "rejected": "boundary",
        "tested": "actual-symbol",
    }
    if kind != expected_kinds[lifecycle]:
        lib.fail(f"{requirement['id']} has target incompatible with lifecycle")
    if kind == "boundary":
        if not isinstance(value, str) or re.fullmatch(
            r"boundary:[a-z0-9.-]+", value
        ) is None:
            lib.fail(f"{requirement['id']} has invalid caller boundary")
    else:
        lib.validate_repository_target(value, requirement["id"])
        if kind in {"actual-symbol", "blocker", "legacy-boundary"}:
            lib.require_actual_target(value, requirement["id"])
        if kind == "legacy-boundary" and "brynja-legacy" not in value:
            lib.fail(f"{requirement['id']} legacy target is not isolated")


def validate_tests_and_evidence(requirement: dict) -> None:
    tests = requirement["tests"]
    if not isinstance(tests, list) or not tests:
        lib.fail(f"{requirement['id']} requires test targets")
    actual_tests = 0
    for test in tests:
        if set(test) != {"status", "target"} or test["status"] not in {
            "actual",
            "planned",
        }:
            lib.fail(f"{requirement['id']} has malformed test target")
        target = lib.validate_repository_target(
            test["target"], f"{requirement['id']} test"
        )
        if test["status"] == "actual":
            actual_tests += 1
            lib.require_actual_target(target, f"{requirement['id']} test")
    lifecycle = requirement["lifecycle"]
    if lifecycle in {"tested", "evidenced"} and actual_tests == 0:
        lib.fail(f"{requirement['id']} lifecycle requires an actual test")
    if lifecycle in {"planned", "implemented"} and actual_tests:
        lib.fail(f"{requirement['id']} claims tests before tested lifecycle")

    evidence = requirement["evidence"]
    if not isinstance(evidence, list) or len(evidence) != len(set(evidence)):
        lib.fail(f"{requirement['id']} has invalid evidence")
    if lifecycle == "evidenced":
        if not evidence:
            lib.fail(f"{requirement['id']} evidenced lifecycle lacks evidence")
        for target in evidence:
            target = lib.validate_repository_target(
                target, f"{requirement['id']} evidence"
            )
            lib.require_actual_target(target, f"{requirement['id']} evidence")
    elif evidence:
        lib.fail(f"{requirement['id']} has premature evidence")


def validate_requirement(
    requirement: dict,
    versions: set[str],
    rfcs: dict[str, dict],
    surface_map: dict[str, dict],
    registry_hashes: dict[str, str],
) -> dict:
    if set(requirement) != REQUIREMENT_FIELDS:
        lib.fail(f"{requirement.get('id')} has unexpected requirement fields")
    requirement_id = requirement["id"]
    if not isinstance(requirement_id, str) or lib.ID_PATTERN.fullmatch(
        requirement_id
    ) is None:
        lib.fail(f"invalid stable requirement ID {requirement_id!r}")
    if not isinstance(requirement["revision"], int) or requirement["revision"] < 1:
        lib.fail(f"{requirement_id} has invalid revision")
    if requirement["lifecycle"] not in lib.LIFECYCLES:
        lib.fail(f"{requirement_id} has unknown lifecycle")
    expected = lib.LIFECYCLE_DECISIONS[requirement["lifecycle"]]
    actual = (requirement["applicability"], requirement["decision"])
    if requirement["decision"] != "deviate" and actual != expected:
        lib.fail(f"{requirement_id} lifecycle decision is inconsistent")
    if requirement["owner"] not in versions:
        lib.fail(f"{requirement_id} has absent or unknown owner")
    if requirement["scope"] not in {"governance", "protocol"}:
        lib.fail(f"{requirement_id} has unknown scope")
    if requirement["scope"] == "protocol" and requirement["lifecycle"] in {
        "evidenced",
        "implemented",
        "tested",
    }:
        lib.fail(f"{requirement_id} prematurely claims protocol implementation")
    if not isinstance(requirement["statement"], str) or len(
        requirement["statement"].strip()
    ) < 30:
        lib.fail(f"{requirement_id} requires a paraphrased statement")
    if not isinstance(requirement["residual"], str) or len(
        requirement["residual"].strip()
    ) < 20:
        lib.fail(f"{requirement_id} requires residual context")

    source, section_text = resolve_source(
        requirement["source"], requirement_id, rfcs, surface_map
    )
    if (
        source["kind"] == "rfc"
        and source["lifecycle"] != "current"
        and requirement["lifecycle"] != "legacy"
    ):
        lib.fail(f"{requirement_id} treats obsolete authority as current")
    if source["kind"] == "iana":
        source["snapshot_sha256"] = registry_hashes[source["collection"]]
    validate_strength(requirement, section_text)
    validate_targets(requirement)
    validate_tests_and_evidence(requirement)

    decision_ids = requirement["decision_ids"]
    if (
        not isinstance(decision_ids, list)
        or not decision_ids
        or len(decision_ids) != len(set(decision_ids))
    ):
        lib.fail(f"{requirement_id} has missing or duplicate decisions")
    unknown = set(decision_ids) - set(surface_map)
    if unknown:
        lib.fail(f"{requirement_id} references unknown decisions: {sorted(unknown)}")
    return {**requirement, "source": source}


def build_matrix(
    policy: dict | None = None,
    ledger: dict | None = None,
    register: dict | None = None,
) -> tuple[dict, dict]:
    policy = policy or lib.read_json(lib.POLICY)
    ledger = ledger or lib.read_json(standards.LEDGER)
    register = register or lib.read_json(surfaces.REGISTER)
    if not all(isinstance(value, dict) for value in (policy, ledger, register)):
        lib.fail("requirement policy, ledger, and surface register must be objects")
    if set(policy) != {
        "requirements",
        "schema",
        "source_ledger_sha256",
        "surface_register_sha256",
    } or policy["schema"] != 1:
        lib.fail("requirement policy has invalid schema or fields")
    validate_binding(policy, ledger, register)

    versions = roadmap_versions()
    rfcs = {f"rfc:{entry['number']}": entry for entry in ledger["rfcs"]}
    surface_map = {entry["id"]: entry for entry in register["surfaces"]}
    registry_hashes = collection_hashes(ledger)
    requirements = [
        validate_requirement(
            requirement,
            versions,
            rfcs,
            surface_map,
            registry_hashes,
        )
        for requirement in policy["requirements"]
    ]
    ids = [requirement["id"] for requirement in requirements]
    if len(ids) != len(set(ids)):
        lib.fail("requirement policy has duplicate stable IDs")
    requirements.sort(key=lambda requirement: requirement["id"])
    matrix = {
        "policy_sha256": standards.sha256(standards.json_bytes(policy)),
        "requirements": requirements,
        "schema": 1,
        "source_ledger_sha256": policy["source_ledger_sha256"],
        "surface_register_sha256": policy["surface_register_sha256"],
    }
    return matrix, lib.build_indexes(requirements)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    matrix, indexes = build_matrix()
    artifacts = {
        lib.COVERAGE: lib.render_coverage(matrix, indexes),
        lib.INDEXES: standards.json_bytes(indexes),
        lib.MATRIX: standards.json_bytes(matrix),
        lib.SCHEMA: standards.json_bytes(lib.schema_document()),
    }
    if args.write:
        lib.DIRECTORY.mkdir(exist_ok=True)
        for path, data in artifacts.items():
            path.write_bytes(data)
        print("wrote normative requirement schema, matrix, indexes, and coverage")
    else:
        for path, data in artifacts.items():
            if not path.is_file() or path.read_bytes() != data:
                lib.fail(f"normative requirement artifact is stale: {path}")
        print(
            f"{len(matrix['requirements'])} pilot requirements are explicit "
            "and reproducible"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
