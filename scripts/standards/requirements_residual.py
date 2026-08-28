#!/usr/bin/env python3
"""v0.3.5 optional, legacy, operational, and residual closure."""

from __future__ import annotations

import tomllib
from collections import defaultdict

import requirements_lib as lib
import requirements_mapping as mapping
import requirements_sections as sections
import requirements_validation as validation
import standards_lib as standards
POLICY = lib.DIRECTORY / "residual-policy.toml"
SECTION_POLICY = lib.DIRECTORY / "residual-sections.toml"
GROUP_FIELDS = {
    "disposition",
    "domain",
    "id",
    "owner",
    "sources",
    "surface_ids",
}
REGISTRY_FIELDS = {"id", "source", "surface"}
DISPOSITION_LIFECYCLE = {
    "caller-owned": "caller-owned",
    "future-work": "planned",
    "intentionally-rejected": "rejected",
    "implemented": "tested",
    "legacy-only": "legacy",
    "safely-ignored": "planned",
}
def local_prefix(filename: str) -> str:
    return "riscv:" if filename.startswith("RISCV.") else "nist:" if filename.startswith("NIST.") else "itu:"
def read_policy() -> dict:
    try:
        with POLICY.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        lib.fail(f"{POLICY}: invalid residual policy: {error}")
def source_map(ledger: dict) -> dict[str, dict]:
    result = {
        f"rfc:{entry['number']}": {**entry, "kind": "rfc"}
        for entry in ledger["rfcs"]
    }
    result.update(
        {
            local_prefix(entry["filename"]) + entry["filename"]: {**entry, "kind": "local"}
            for entry in ledger["local_authorities"]
        }
    )
    result.update(
        {
            f"iana:{entry['id']}": {
                **entry,
                "kind": "iana",
                "lifecycle": "current",
            }
            for entry in ledger["registries"]
        }
    )
    return result
def resolve_source(identifier: str, sources: dict[str, dict]) -> dict:
    entry = sources.get(identifier)
    if entry is None:
        lib.fail(f"residual policy references unknown authority: {identifier}")
    common = {
        "authority_role": entry.get("lifecycle", "current"),
        "domains": entry["domains"],
        "id": identifier,
        "kind": entry["kind"],
        "milestones": entry["milestones"],
        "sha256": entry["sha256"],
    }
    if entry["kind"] == "rfc":
        return {
            **common,
            "errata": entry["errata"],
            "sections": [],
            "status": entry["status"],
        }
    if entry["kind"] == "local":
        return {**common, "role": entry["role"]}
    return {**common, "collection": entry["id"]}


def covered_surface_ids(
    foundation: list[dict],
    domain: dict,
    transport: dict,
) -> set[str]:
    covered = {
        item["id"]
        for artifact in (domain, transport)
        for item in artifact["surfaces"]
        if item["coverage"] == "requirement"
    }
    covered.update(
        decision
        for requirement in foundation
        for decision in requirement["decision_ids"]
    )
    return covered


def _target(lifecycle: str, surface: dict) -> dict:
    if lifecycle == "blocked":
        blocker = surface.get("source_blocker")
        if blocker is None:
            lib.fail("blocked residual requirement lacks a source blocker")
        return {
            "kind": "blocker",
            "target": f"requirements/authority-claims.toml#{blocker}",
        }
    if lifecycle == "legacy":
        target = surface["code_target"]
        if not (lib.ROOT / target).is_file() or "brynja-legacy" not in target:
            target = "crates/brynja-legacy/src/lib.rs"
        return {"kind": "legacy-boundary", "target": target}
    if lifecycle in {"caller-owned", "rejected"}:
        label = surface["domain"].replace("_", "-")
        return {"kind": "boundary", "target": f"boundary:{label}.{surface['owner']}"}
    if lifecycle in {"evidenced", "implemented", "tested"}:
        return {"kind": "actual-symbol", "target": surface["code_target"]}
    return {"kind": "planned-symbol", "target": surface["code_target"]}


def _invariants(domain: str, lifecycle: str) -> list[str]:
    values = ["resource-bound", "validation", "work-bound"]
    if domain in {"dtls", "ech", "hpke", "hybrid", "tls", "tls12"}:
        values.append("version-separation")
    if domain in {"cryptography", "entropy", "hpke", "hybrid"}:
        values.extend(["key-lifecycle", "side-channel"])
    if lifecycle == "legacy":
        values.append("algorithm-admission")
    return values


def _tests(surface: dict, verified: bool) -> list[dict]:
    path, _separator, _anchor_value = surface["test_target"].partition("#")
    return [
        {
            "polarity": "positive",
            "status": "actual" if verified else "planned",
            "target": surface["test_target"],
        },
        {
            "polarity": "negative",
            "status": "actual" if verified else "planned",
            "target": f"{path}#reject_invalid_and_exhausted",
        },
    ]


def make_requirement(
    raw: dict,
    surface: dict,
    sources: dict[str, dict],
    decision_ids: list[str],
    *,
    lifecycle: str | None = None,
) -> dict:
    lifecycle = lifecycle or raw.get(
        "lifecycle", DISPOSITION_LIFECYCLE[surface["disposition"]]
    )
    applicability, decision = lib.LIFECYCLE_DECISIONS[lifecycle]
    requirement = {
        "applicability": applicability,
        "decision": decision,
        "decision_ids": sorted(decision_ids),
        "deviation_rationale": None,
        "domain": surface["domain"],
        "evidence": [],
        "evidence_gap": (
            "Executable boundary tests are linked and passing; independent "
            "review remains unresolved at this implementation stop."
            if raw.get("verified", False)
            else "Executable vectors, fault campaigns, interoperability, and "
            f"independent audit evidence remain unresolved until {surface['owner']}."
        ),
        "id": raw["id"],
        "invariants": _invariants(surface["domain"], lifecycle),
        "lifecycle": lifecycle,
        "mapping_rationale": (
            "This residual group binds every previously uncovered surface in "
            "one exact domain, owner, and disposition class to reviewed locked "
            "authorities, a single implementation boundary, and paired tests."
        ),
        "mapping_scope": "reviewed-domain",
        "owner": surface["owner"],
        "profile": "optional-legacy-residual",
        "residual": (
            "No protocol implementation, interoperability, audit, source-rights, "
            "or production-readiness claim is made by this planning requirement."
        ),
        "revision": raw.get("revision", 1),
        "scope": "protocol",
        "sources": [resolve_source(item, sources) for item in raw["sources"]],
        "statement": surface["rationale"],
        "strength": "INVARIANT",
        "targets": [_target(
            lifecycle,
            {**surface, "source_blocker": raw.get("blocker")},
        )],
        "tests": _tests(surface, raw.get("verified", False)),
        "work_bound": (
            "Inputs, parsing, retained bytes, retries, provider operations, "
            "state transitions, and outputs require explicit caller-owned ceilings."
        ),
    }
    validation.validate_targets(requirement)
    stripped = [
        {"status": item["status"], "target": item["target"]}
        for item in requirement["tests"]
    ]
    validation.validate_tests_and_evidence({**requirement, "tests": stripped})
    return requirement


def validate_policy(
    policy: dict,
    ledger: dict,
    register: dict,
    versions: set[str],
) -> None:
    if (
        set(policy)
        != {
            "milestone",
            "registry_requirement",
            "schema",
            "source_ledger_sha256",
            "surface_group",
            "surface_register_sha256",
        }
        or policy["schema"] != 1
        or policy["milestone"] != "0.3.5"
        or policy["source_ledger_sha256"]
        != standards.sha256(standards.json_bytes(ledger))
        or policy["surface_register_sha256"]
        != standards.sha256(standards.json_bytes(register))
    ):
        lib.fail("residual policy has invalid schema, milestone, or binding")
    groups = policy["surface_group"]
    for item in groups:
        if (
            not GROUP_FIELDS <= set(item)
            or set(item)
            - GROUP_FIELDS
            - {"blocker", "lifecycle", "revision", "verified"}
        ) or (
            item["owner"] not in versions
            or item["disposition"] not in DISPOSITION_LIFECYCLE
            or not isinstance(item["sources"], list)
            or (
                not item["sources"]
                and item.get("lifecycle") != "blocked"
            )
            or not isinstance(item["surface_ids"], list)
            or not item["surface_ids"]
            or len(item["surface_ids"]) != len(set(item["surface_ids"]))
            or not isinstance(item.get("revision", 1), int)
            or item.get("revision", 1) < 1
            or not isinstance(item.get("verified", False), bool)
            or (
                (item.get("lifecycle") == "blocked")
                != isinstance(item.get("blocker"), str)
            )
        ):
            lib.fail("residual policy has a malformed surface group")
    if any(not REGISTRY_FIELDS <= set(item) or set(item) - REGISTRY_FIELDS - {"revision"}
           or not isinstance(item.get("revision", 1), int) or item.get("revision", 1) < 1 for item in policy["registry_requirement"]):
        lib.fail("residual policy has a malformed registry requirement")
    ids = [item["id"] for key in ("surface_group", "registry_requirement") for item in policy[key]]
    if len(ids) != len(set(ids)) or any(lib.ID_PATTERN.fullmatch(item) is None for item in ids):
        lib.fail("residual policy has duplicate or malformed stable IDs")


def build(
    ledger: dict,
    register: dict,
    versions: set[str],
    foundation: list[dict],
    domain: dict,
    transport: dict,
    existing_requirements: list[dict],
    policy: dict | None = None,
    section_policy: dict | None = None,
) -> tuple[list[dict], dict, str]:
    policy = policy or read_policy()
    section_policy = section_policy or sections.read_policy(SECTION_POLICY)
    validate_policy(policy, ledger, register, versions)
    surfaces = {item["id"]: item for item in register["surfaces"]}
    covered = covered_surface_ids(foundation, domain, transport)
    remaining = [item for item in register["surfaces"] if item["id"] not in covered]
    remaining_ids = {item["id"] for item in remaining}
    configured_ids = [
        surface_id
        for item in policy["surface_group"]
        for surface_id in item["surface_ids"]
    ]
    if (
        len(configured_ids) != len(set(configured_ids))
        or set(configured_ids) != remaining_ids
    ):
        lib.fail(
            "residual surface identities differ: "
            f"missing={sorted(remaining_ids - set(configured_ids))}, "
            f"stale={sorted(set(configured_ids) - remaining_ids)}"
        )
    authorities = source_map(ledger)
    requirements = []
    assignments = []
    for raw in sorted(policy["surface_group"], key=lambda item: item["id"]):
        key = (raw["domain"], raw["owner"], raw["disposition"])
        candidates = [surfaces[surface_id] for surface_id in raw["surface_ids"]]
        incompatible = [
            item["id"]
            for item in candidates
            if (item["domain"], item["owner"], item["disposition"]) != key
        ]
        if incompatible:
            lib.fail(f"{raw['id']} contains incompatible surfaces: {incompatible}")
        blockers = {item.get("source_blocker") for item in candidates}
        if blockers != {raw.get("blocker")}:
            lib.fail(f"{raw['id']} source blocker differs across surfaces")
        unknown = set(raw["sources"]) - set(authorities)
        if unknown:
            lib.fail(f"residual policy references unknown authority: {sorted(unknown)}")
        unrelated = (
            []
            if raw.get("lifecycle") == "blocked" and not raw["sources"]
            else [
                item["id"]
                for item in candidates
                if not set(raw["sources"]).intersection(
                    item["normative_sources"]
                )
            ]
        )
        if unrelated:
            lib.fail(f"{raw['id']} has unrelated surfaces: {unrelated}")
        boundaries = {
            (item["code_target"], item["test_target"]) for item in candidates
        }
        if len(boundaries) != 1:
            lib.fail(f"{raw['id']} must use one implementation and test boundary")
        representative = candidates[0]
        expected = raw.get("lifecycle", DISPOSITION_LIFECYCLE[key[2]])
        if key[2] not in mapping.EXPECTED_DISPOSITIONS[expected]:
            lib.fail(f"{raw['id']} lifecycle conflicts with its residual group")
        requirement = make_requirement(
            raw,
            representative,
            authorities,
            raw["surface_ids"],
        )
        requirements.append(requirement)
        assignments.extend(
            {
                "coverage": "requirement",
                "disposition": item["disposition"],
                "domain": item["domain"],
                "id": item["id"],
                "owner": item["owner"],
                "requirement_id": requirement["id"],
            }
            for item in candidates
        )
    for raw in policy["registry_requirement"]:
        surface = surfaces.get(raw["surface"])
        if surface is None or raw["source"] not in surface["normative_sources"]:
            lib.fail(f"{raw['id']} has an invalid registry source surface")
        requirements.append(
            make_requirement(
                {**raw, "sources": [raw["source"]]},
                surface,
                authorities,
                [surface["id"]],
            )
        )
    ids = [item["id"] for item in requirements]
    if len(ids) != len(set(ids)):
        lib.fail("residual requirements have duplicate stable IDs")
    residual_authority_ids = {
        source["id"]
        for requirement in requirements
        for source in requirement["sources"]
    }
    residual_authorities = {
        identifier: authorities[identifier]
        for identifier in residual_authority_ids
    }
    sections.validate_policy(
        section_policy,
        SECTION_POLICY,
        "0.3.5",
        standards.sha256(standards.json_bytes(ledger)),
    )
    requirements, section_coverage = sections.apply(
        requirements,
        residual_authorities,
        section_policy,
        minimum_revision=1,
        mapping_suffix=(
            "Exact normative sections are assigned only by the reviewed "
            "v0.3.5 residual section policy; RFC-wide inheritance is forbidden."
        ),
    )
    requirement_map = {item["id"]: item for item in requirements}
    for assignment in assignments:
        linked = requirement_map[assignment["requirement_id"]]["decision_ids"]
        if assignment["id"] not in linked:
            lib.fail(
                f"{assignment['id']} is not linked from "
                f"{assignment['requirement_id']}"
            )
    all_requirements = existing_requirements + requirements
    cited = set()
    for requirement in all_requirements:
        raw_sources = requirement.get("sources")
        if raw_sources is None:
            raw_sources = [requirement.get("source")]
        for source in raw_sources:
            identifier = source.get("id")
            if identifier is None and source.get("kind") == "iana":
                identifier = f"iana:{source['collection']}"
            if identifier is not None:
                cited.add(identifier)
    missing = set(authorities) - cited
    if missing:
        lib.fail(f"source-to-requirement closure is incomplete: {sorted(missing)}")
    digest = standards.sha256(
        standards.json_bytes(
            {"policy": policy, "section_policy": section_policy}
        )
    )
    coverage = _coverage(
        requirements,
        assignments,
        digest,
        section_coverage,
        residual_authorities,
    )
    return requirements, coverage, digest


def _coverage(
    requirements: list[dict],
    assignments: list[dict],
    digest: str,
    section_coverage: dict[tuple[str, str], dict],
    raw_authorities: dict[str, dict],
) -> dict:
    by_source: dict[str, list[str]] = defaultdict(list)
    source_records = {}
    for requirement in requirements:
        for source in requirement["sources"]:
            by_source[source["id"]].append(requirement["id"])
            base = {key: value for key, value in source.items() if key != "sections"}
            previous = source_records.setdefault(source["id"], base)
            if previous != base:
                lib.fail(f"residual authority identity differs: {source['id']}")
    inventory = sections.section_inventory(raw_authorities)
    authorities = []
    for identifier, source in sorted(source_records.items()):
        record = dict(source)
        record["requirement_ids"] = sorted(set(by_source[identifier]))
        source_sections = {
            section: decision
            for (source_id, section), decision in section_coverage.items()
            if source_id == identifier
        }
        if source_sections:
            record["normative_sections"] = [
                {
                    "anchor": sections.anchor(inventory[(identifier, section)]),
                    **decision,
                    "section": section,
                    "section_sha256": lib.section_hash(
                        inventory[(identifier, section)]
                    ),
                }
                for section, decision in sorted(source_sections.items())
            ]
        authorities.append(record)
    mapped_sections = sum(
        "requirement_ids" in decision for decision in section_coverage.values()
    )
    return {
        "authorities": authorities,
        "authority_count": len(authorities),
        "mapped_normative_section_count": mapped_sections,
        "normative_section_count": len(section_coverage),
        "policy_sha256": digest,
        "requirement_count": len(requirements),
        "schema": 1,
        "surface_count": len(assignments),
        "surfaces": sorted(assignments, key=lambda item: item["id"]),
    }
