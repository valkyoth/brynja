#!/usr/bin/env python3
"""Validate and generate Brynja's normative requirement matrix pilot."""

from __future__ import annotations

import argparse
import re

import requirements_lib as lib
import requirements_history as history
import requirements_mapping as mapping
import requirements_closure as closure
import requirements_domain as domain
import requirements_residual as residual
import requirements_sections as sections
import requirements_transport as transport
import requirements_validation as validation
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
    "mapping_rationale",
    "mapping_scope",
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


validate_targets = validation.validate_targets
validate_tests_and_evidence = validation.validate_tests_and_evidence


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
    mapping.validate(requirement, source, surface_map)
    return {**requirement, "source": source}


def build_matrix(
    policy: dict | None = None,
    ledger: dict | None = None,
    register: dict | None = None,
    previous: dict | None | object | bool = history.AUTO,
    include_domains: bool | None = None,
) -> tuple[dict, dict]:
    custom_inputs = any(value is not None for value in (policy, ledger, register))
    if include_domains is None:
        include_domains = not custom_inputs
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
    if include_domains:
        domain_requirements, _domain_coverage, domain_hash = domain.build(
            ledger,
            register,
            versions,
        )
        requirements.extend(domain_requirements)
        transport_requirements, _transport_coverage, transport_hash = (
            transport.build(ledger, register, versions)
        )
        requirements.extend(transport_requirements)
        residual_requirements, _residual_coverage, residual_hash = residual.build(
            ledger,
            register,
            versions,
            requirements[: len(policy["requirements"])],
            _domain_coverage,
            _transport_coverage,
            requirements,
        )
        requirements.extend(residual_requirements)
    else:
        _scope, _domain_requirements, domain_hash = domain.load_policy()
        _scope, _transport_requirements, transport_hash = (
            transport.load_policy(ledger)
        )
        residual_hash = standards.sha256(
            standards.json_bytes(
                {
                    "policy": residual.read_policy(),
                    "section_policy": sections.read_policy(
                        residual.SECTION_POLICY
                    ),
                }
            )
        )
    ids = [requirement["id"] for requirement in requirements]
    if len(ids) != len(set(ids)):
        lib.fail("requirement policy has duplicate stable IDs")
    requirements.sort(key=lambda requirement: requirement["id"])
    if previous is not False:
        if previous is history.AUTO:
            previous = history.load_matrix()
        history.validate(previous, requirements, validate_transition)
    matrix = {
        "closure_policy_sha256": standards.sha256(
            standards.json_bytes(closure.read_claims())
        ),
        "domain_policy_sha256": domain_hash,
        "policy_sha256": standards.sha256(standards.json_bytes(policy)),
        "requirements": requirements,
        "residual_policy_sha256": residual_hash,
        "schema": 5,
        "source_ledger_sha256": policy["source_ledger_sha256"],
        "surface_register_sha256": policy["surface_register_sha256"],
        "transport_policy_sha256": transport_hash,
    }
    return matrix, lib.build_indexes(requirements)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    matrix, indexes = build_matrix()
    _domain_requirements, domain_coverage, _domain_hash = domain.build(
        lib.read_json(standards.LEDGER),
        lib.read_json(surfaces.REGISTER),
        roadmap_versions(),
    )
    _transport_requirements, transport_coverage, _transport_hash = (
        transport.build(
            lib.read_json(standards.LEDGER),
            lib.read_json(surfaces.REGISTER),
            roadmap_versions(),
        )
    )
    foundation_ids = {
        item["id"] for item in lib.read_json(lib.POLICY)["requirements"]
    }
    existing = matrix["requirements"][:]
    residual_ids = {
        item["id"]
        for item in residual.read_policy()["surface_group"]
        + residual.read_policy()["registry_requirement"]
    }
    existing = [item for item in existing if item["id"] not in residual_ids]
    _residual_requirements, residual_coverage, _residual_hash = residual.build(
        lib.read_json(standards.LEDGER),
        lib.read_json(surfaces.REGISTER),
        roadmap_versions(),
        [
            item
            for item in matrix["requirements"]
            if item["id"] in foundation_ids
        ],
        domain_coverage,
        transport_coverage,
        existing,
    )
    closure_artifact = closure.build(
        lib.read_json(standards.LEDGER),
        lib.read_json(surfaces.REGISTER),
        matrix,
        domain_coverage,
        transport_coverage,
        residual_coverage,
        foundation_ids,
    )
    artifacts = {
        lib.CLOSURE: standards.json_bytes(closure_artifact),
        lib.COVERAGE: lib.render_coverage(matrix, indexes),
        lib.DOMAIN_COVERAGE: standards.json_bytes(domain_coverage),
        lib.TRANSPORT_COVERAGE: standards.json_bytes(transport_coverage),
        lib.INDEXES: standards.json_bytes(indexes),
        lib.MATRIX: standards.json_bytes(matrix),
        lib.RESIDUAL_COVERAGE: standards.json_bytes(residual_coverage),
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
            f"{len(matrix['requirements'])} requirements are explicit "
            "and reproducible"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
