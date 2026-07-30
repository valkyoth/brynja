#!/usr/bin/env python3
"""Explicit normative-section bindings for reviewed requirement bundles."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import requirements_lib as lib
import standards_lib as standards


DISPOSITIONS = {"caller-owned", "excluded", "not-applicable"}
NORMATIVE = re.compile(r"\b(?:MUST NOT|SHOULD NOT|MUST|SHOULD|MAY)\b")


def read_policy(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        lib.fail(f"{path}: invalid section policy: {error}")


def anchor(section_text: str) -> str:
    value = section_text[:160].strip()
    if len(value) < 20 or section_text.count(value) != 1:
        lib.fail("normative section lacks a unique extraction anchor")
    return value


def section_inventory(authorities: dict[str, dict]) -> dict[tuple[str, str], str]:
    result = {}
    for source_id, entry in authorities.items():
        if "number" not in entry:
            continue
        path = lib.ROOT / "rfc" / f"rfc{entry['number']}.txt"
        for section, text in lib.rfc_sections(path).items():
            if NORMATIVE.search(text) is None:
                continue
            result[(source_id, section)] = text
    return result


def validate_policy(
    policy: dict,
    path: Path,
    milestone: str,
    ledger_hash: str,
) -> None:
    if (
        set(policy) != {
            "binding",
            "exclusion",
            "milestone",
            "revisions",
            "schema",
            "source_ledger_sha256",
        }
        or policy["schema"] != 1
        or policy["milestone"] != milestone
        or policy["source_ledger_sha256"] != ledger_hash
        or not isinstance(policy["binding"], list)
        or not isinstance(policy["exclusion"], list)
        or not isinstance(policy["revisions"], dict)
    ):
        lib.fail(f"{path}: invalid normative-section policy")


def apply(
    requirements: list[dict],
    authorities: dict[str, dict],
    policy: dict,
    *,
    minimum_revision: int = 2,
    mapping_suffix: str | None = None,
) -> tuple[list[dict], dict[tuple[str, str], dict]]:
    requirement_map = {item["id"]: item for item in requirements}
    inventory = section_inventory(authorities)
    assignments: dict[tuple[str, str], set[str]] = {}
    pair_sections: dict[tuple[str, str], set[str]] = {}
    for binding in policy["binding"]:
        if set(binding) != {
            "rationale",
            "requirement_id",
            "sections",
            "source_id",
        }:
            lib.fail("malformed normative-section binding")
        requirement = requirement_map.get(binding["requirement_id"])
        source_ids = (
            {source["id"] for source in requirement["sources"]}
            if requirement is not None
            else set()
        )
        if (
            requirement is None
            or binding["source_id"] not in source_ids
            or not isinstance(binding["sections"], list)
            or not binding["sections"]
            or len(binding["sections"]) != len(set(binding["sections"]))
            or not isinstance(binding["rationale"], str)
            or len(binding["rationale"].strip()) < 80
        ):
            lib.fail("invalid normative-section binding")
        pair = (binding["requirement_id"], binding["source_id"])
        if pair in pair_sections:
            lib.fail("duplicate requirement and source section binding")
        pair_sections[pair] = set(binding["sections"])
        for section in binding["sections"]:
            key = (binding["source_id"], section)
            if key not in inventory:
                lib.fail(f"binding references non-normative section: {key}")
            assignments.setdefault(key, set()).add(binding["requirement_id"])

    exclusions = {}
    for exclusion in policy["exclusion"]:
        if set(exclusion) != {
            "disposition",
            "rationale",
            "section",
            "source_id",
        }:
            lib.fail("malformed normative-section exclusion")
        key = (exclusion["source_id"], exclusion["section"])
        if (
            key not in inventory
            or key in exclusions
            or key in assignments
            or exclusion["disposition"] not in DISPOSITIONS
            or not isinstance(exclusion["rationale"], str)
            or len(exclusion["rationale"].strip()) < 80
        ):
            lib.fail("invalid normative-section exclusion")
        exclusions[key] = exclusion

    missing = set(inventory) - set(assignments) - set(exclusions)
    if missing:
        lib.fail(f"unmapped normative sections: {sorted(missing)}")
    bound_requirements = {
        requirement_id for requirement_id, _source_id in pair_sections
    }
    if (
        set(policy["revisions"]) != bound_requirements
        or any(
            not isinstance(value, int) or value < minimum_revision
            for value in policy["revisions"].values()
        )
    ):
        lib.fail("normative-section revision set is incomplete")
    cited_pairs = {
        (requirement["id"], source["id"])
        for requirement in requirements
        for source in requirement["sources"]
        if source["kind"] == "rfc"
        and any(key[0] == source["id"] for key in inventory)
    }
    if set(pair_sections) != cited_pairs:
        lib.fail(
            "normative requirement/source binding set differs: "
            f"missing={sorted(cited_pairs - set(pair_sections))}, "
            f"stale={sorted(set(pair_sections) - cited_pairs)}"
        )

    resolved = []
    for requirement in requirements:
        sources = []
        for source in requirement["sources"]:
            if source["kind"] != "rfc":
                sources.append(source)
                continue
            pair = (requirement["id"], source["id"])
            if pair not in pair_sections:
                sources.append(source)
                continue
            source_sections = pair_sections[pair]
            records = [
                {
                    "anchor": anchor(inventory[(source["id"], section)]),
                    "section": section,
                    "section_sha256": lib.section_hash(
                        inventory[(source["id"], section)]
                    ),
                }
                for section in sorted(source_sections)
            ]
            sources.append({**source, "sections": records})
        revision = policy["revisions"].get(
            requirement["id"], requirement["revision"]
        )
        mapping_rationale = requirement["mapping_rationale"]
        if requirement["id"] in bound_requirements and mapping_suffix is not None:
            mapping_rationale = f"{mapping_rationale} {mapping_suffix}"
        resolved.append(
            {
                **requirement,
                "mapping_rationale": mapping_rationale,
                "revision": revision,
                "sources": sources,
            }
        )
    coverage = {
        key: (
            {"requirement_ids": sorted(assignments[key])}
            if key in assignments
            else {
                "disposition": exclusions[key]["disposition"],
                "rationale": exclusions[key]["rationale"],
            }
        )
        for key in inventory
    }
    return resolved, coverage
