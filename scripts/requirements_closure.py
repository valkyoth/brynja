#!/usr/bin/env python3
"""Generate and validate v0.3.5 bidirectional planning closure."""

from __future__ import annotations

import re
import tomllib
from collections import defaultdict

import requirements_lib as lib
import standards_lib as standards


CLAIMS = lib.DIRECTORY / "authority-claims.toml"
VERSION_CELL = re.compile(r"^`(H?\d+\.\d+(?:\.\d+)?)`$")


def read_claims() -> dict:
    try:
        with CLAIMS.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        lib.fail(f"{CLAIMS}: invalid authority claims: {error}")


def roadmap() -> list[dict]:
    text = (lib.ROOT / "docs/VERSION_PLAN.md").read_text(encoding="utf-8")
    result = []
    seen = set()
    for line in text.splitlines():
        cells = [item.strip() for item in line.strip().strip("|").split("|")]
        if not cells or VERSION_CELL.fullmatch(cells[0]) is None:
            continue
        version = VERSION_CELL.fullmatch(cells[0]).group(1)
        title = cells[1] if len(cells) == 3 else "Legacy package stage"
        scope = cells[-1]
        if version in seen:
            lib.fail(f"duplicate roadmap version in closure: {version}")
        seen.add(version)
        result.append(
            {
                "scope": lib.normalize(scope),
                "title": lib.normalize(title),
                "version": version,
            }
        )
    if not result:
        lib.fail("roadmap closure found no version rows")
    return result


def authority_map(ledger: dict) -> dict[str, dict]:
    result = {
        f"rfc:{item['number']}": item for item in ledger["rfcs"]
    }
    result.update(
        {
            (
                "nist:"
                if item["filename"].startswith("NIST.")
                else "riscv:"
                if item["filename"].startswith("RISCV.")
                else "itu:"
            )
            + item["filename"]: item
            for item in ledger["local_authorities"]
        }
    )
    result.update(
        {f"iana:{item['id']}": item for item in ledger["registries"]}
    )
    return result


def source_id(source: dict) -> str:
    identifier = source.get("id")
    if identifier is not None:
        return identifier
    if source.get("kind") == "iana":
        return f"iana:{source['collection']}"
    lib.fail("requirement closure found an unidentified source")


def requirement_sources(requirement: dict) -> set[str]:
    sources = requirement.get("sources")
    if sources is None:
        sources = [requirement.get("source")]
    return {
        source_id(source)
        for source in sources
    }


def validate_claims(
    claims: dict,
    authorities: dict[str, dict],
    versions: set[str],
    register: dict,
    ledger: dict,
) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    required = {
        "blocker",
        "local_right",
        "milestone",
        "mutable_authority",
        "plan_boundary",
        "reviewed_at",
        "schema",
    }
    if (
        set(claims) != required
        or claims["schema"] != 1
        or claims["milestone"] != "0.3.5"
        or claims["reviewed_at"] != "2026-07-30"
    ):
        lib.fail("authority claims have invalid schema, milestone, or review date")
    local_ids = {
        identifier
        for identifier, entry in authorities.items()
        if "filename" in entry
    }
    rights = _unique(claims["local_right"], "authority", "local rights")
    if set(rights) != local_ids:
        lib.fail("local authority rights coverage is incomplete")
    for identifier, item in rights.items():
        if (
            set(item) != {"authority", "distribution", "review"}
            or item["distribution"] != "local-only"
            or len(item["review"].strip()) < 80
        ):
            lib.fail(f"invalid local authority rights record: {identifier}")
    mutable = _unique(
        claims["mutable_authority"], "authority", "mutable authorities"
    )
    expected_mutable = {
        identifier for identifier in authorities if identifier.startswith("iana:")
    } | {
        "nist:NIST.FIPS.203.pdf",
        "nist:NIST.SP.800-227.pdf",
        "nist:NIST.SP.800-90Ar1.pdf",
        "nist:NIST.SP.800-90B.pdf",
        "nist:NIST.SP.800-90C.pdf",
    }
    if set(mutable) != expected_mutable:
        lib.fail("mutable authority refresh coverage is incomplete")
    for identifier, item in mutable.items():
        url = item.get("url", "")
        expected_url = authorities[identifier]["url"]
        valid_url = (
            url == expected_url
            if identifier.startswith("iana:")
            else url.startswith("https://csrc.nist.gov/pubs/")
        )
        if (
            set(item)
            != {"authority", "owner", "rationale", "status", "url"}
            or item["owner"] not in versions
            or item["status"] != "refresh-required"
            or not valid_url
            or len(item["rationale"].strip()) < 80
        ):
            lib.fail(f"invalid mutable authority record: {identifier}")
    blockers = _unique(claims["blocker"], "id", "authority blockers")
    if set(blockers) != {
        "ecdhe-ml-kem-groups",
        "fips-validation-baseline",
        "legacy-non-rfc-sources",
    }:
        lib.fail("authority blocker set is incomplete")
    for item in blockers.values():
        expected_status = (
            "resolved" if item["id"] == "ecdhe-ml-kem-groups" else "blocked"
        )
        if (
            item["owner"] not in versions
            or item["status"] != expected_status
            or len(item["rationale"].strip()) < 80
        ):
            lib.fail(f"invalid authority blocker: {item['id']}")
    ledger_blocker = {
        item["id"]: item for item in ledger["blockers"]
    }.get("ecdhe-ml-kem-groups")
    hybrid = blockers["ecdhe-ml-kem-groups"]
    if (
        ledger_blocker is None
        or ledger_blocker["status"] != "resolved"
        or hybrid.get("surface") != "algorithm.ecdhe-ml-kem"
    ):
        lib.fail("hybrid resolution is not bound to the source ledger and surface")
    surface_ids = {item["id"] for item in register["surfaces"]}
    legacy = blockers["legacy-non-rfc-sources"].get("surfaces", [])
    expected_legacy = {
        "legacy.pct",
        "legacy.snp",
        "legacy.ssl1-research",
        "legacy.ssl2",
        "legacy.wtls",
    }
    if set(legacy) != expected_legacy or not set(legacy) <= surface_ids:
        lib.fail("legacy source-rights blocker surface set is incomplete")
    return rights, mutable, blockers


def _unique(items: list[dict], key: str, label: str) -> dict[str, dict]:
    result = {item.get(key): item for item in items}
    if None in result or len(result) != len(items):
        lib.fail(f"{label} have duplicate or missing identities")
    return result


def plan_boundaries(
    claims: dict,
    plans: list[dict],
    source_plans: set[str],
    requirement_plans: set[str],
    blockers: dict[str, dict],
) -> dict[str, dict]:
    result = {}
    for group in claims["plan_boundary"]:
        fields = {"class", "rationale", "versions"}
        if group.get("class") == "authority-blocked":
            fields.add("blocker")
        if set(group) != fields or len(group["rationale"].strip()) < 100:
            lib.fail("malformed plan boundary group")
        if group.get("blocker") not in {None, *blockers}:
            lib.fail("plan boundary references an unknown blocker")
        for version in group["versions"]:
            if version in result:
                lib.fail(f"duplicate plan boundary: {version}")
            result[version] = {
                key: value for key, value in group.items() if key != "versions"
            }
    versions = {item["version"] for item in plans}
    missing = versions - source_plans - requirement_plans
    if set(result) != missing:
        lib.fail(
            "plan-to-source boundary differs: "
            f"missing={sorted(missing - set(result))}, "
            f"stale={sorted(set(result) - missing)}"
        )
    return result


def surface_assignments(
    register: dict,
    coverages: tuple[dict, dict, dict],
    foundation: list[dict],
) -> dict[str, set[str]]:
    assignments: dict[str, set[str]] = defaultdict(set)
    for coverage in coverages:
        for item in coverage["surfaces"]:
            if item["coverage"] == "requirement":
                assignments[item["id"]].add(item["requirement_id"])
    for requirement in foundation:
        for surface in requirement["decision_ids"]:
            assignments[surface].add(requirement["id"])
    expected = {item["id"] for item in register["surfaces"]}
    if set(assignments) != expected or any(not value for value in assignments.values()):
        lib.fail("surface-to-requirement closure is incomplete")
    return assignments


def validate_source_blockers(
    register: dict,
    blockers: dict[str, dict],
    assignments: dict[str, set[str]],
    requirements: dict[str, dict],
) -> None:
    blocker_id = "legacy-non-rfc-sources"
    expected = set(blockers[blocker_id]["surfaces"])
    marked = {
        item["id"]
        for item in register["surfaces"]
        if item.get("source_blocker") == blocker_id
    }
    unknown = {
        item.get("source_blocker")
        for item in register["surfaces"]
        if item.get("source_blocker") not in {None, blocker_id}
    }
    if marked != expected or unknown:
        lib.fail("source-blocked surface linkage is incomplete")
    target = f"requirements/authority-claims.toml#{blocker_id}"
    for surface_id in expected:
        for requirement_id in assignments[surface_id]:
            requirement = requirements[requirement_id]
            if requirement["lifecycle"] != "blocked":
                lib.fail(f"{surface_id} must remain source blocked")
            if requirement["targets"] != [{"kind": "blocker", "target": target}]:
                lib.fail(f"{surface_id} requires its exact source blocker target")


def build(
    ledger: dict,
    register: dict,
    matrix: dict,
    domain: dict,
    transport: dict,
    residual: dict,
    foundation_ids: set[str],
    claims: dict | None = None,
) -> dict:
    claims = claims or read_claims()
    plans = roadmap()
    versions = {item["version"] for item in plans}
    authorities = authority_map(ledger)
    rights, mutable, blockers = validate_claims(
        claims, authorities, versions, register, ledger
    )
    requirements = matrix["requirements"]
    requirement_map = {item["id"]: item for item in requirements}
    if len(requirement_map) != len(requirements):
        lib.fail("closure found duplicate requirement identifiers")
    source_requirements: dict[str, set[str]] = defaultdict(set)
    owner_requirements: dict[str, set[str]] = defaultdict(set)
    for requirement in requirements:
        if requirement["owner"] not in versions:
            lib.fail(f"closure found unknown owner: {requirement['owner']}")
        owner_requirements[requirement["owner"]].add(requirement["id"])
        for identifier in requirement_sources(requirement):
            if identifier not in authorities:
                lib.fail(f"closure found unknown source: {identifier}")
            source_requirements[identifier].add(requirement["id"])
    if set(source_requirements) != set(authorities):
        lib.fail("source-to-requirement closure is incomplete")
    source_plans = {
        version
        for entry in authorities.values()
        for version in entry["milestones"]
    }
    boundaries = plan_boundaries(
        claims,
        plans,
        source_plans,
        set(owner_requirements),
        blockers,
    )
    foundation = [
        requirement
        for requirement in requirements
        if requirement["id"] in foundation_ids
    ]
    surfaces = surface_assignments(
        register, (domain, transport, residual), foundation
    )
    validate_source_blockers(register, blockers, surfaces, requirement_map)
    provisional = [
        item["id"]
        for item in register["surfaces"]
        if item["disposition"] == "future-work"
        and "draft" in standards.json_bytes(item).decode().lower()
    ]
    return {
        "blockers": [blockers[key] for key in sorted(blockers)],
        "local_rights": [rights[key] for key in sorted(rights)],
        "mutable_authorities": [mutable[key] for key in sorted(mutable)],
        "plans": [
            {
                **plan,
                "boundary": boundaries.get(plan["version"]),
                "requirement_ids": sorted(
                    owner_requirements.get(plan["version"], set())
                ),
                "source_ids": sorted(
                    identifier
                    for identifier, entry in authorities.items()
                    if plan["version"] in entry["milestones"]
                ),
            }
            for plan in plans
        ],
        "provisional_surface_count": len(provisional),
        "provisional_surfaces": sorted(provisional),
        "requirements": [
            {
                "decision_ids": item["decision_ids"],
                "id": item["id"],
                "lifecycle": item["lifecycle"],
                "owner": item["owner"],
                "source_ids": sorted(requirement_sources(item)),
            }
            for item in requirements
        ],
        "schema": 1,
        "sources": [
            {
                "id": identifier,
                "milestones": entry["milestones"],
                "requirement_ids": sorted(source_requirements[identifier]),
                "sha256": entry["sha256"],
            }
            for identifier, entry in sorted(authorities.items())
        ],
        "surfaces": [
            {
                "id": identifier,
                "requirement_ids": sorted(surfaces[identifier]),
            }
            for identifier in sorted(surfaces)
        ],
    }
