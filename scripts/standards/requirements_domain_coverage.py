#!/usr/bin/env python3
"""Coverage artifact helpers for the v0.3.3 domain requirement bundle."""

from __future__ import annotations

import re
from collections import Counter

import requirements_lib as lib
import requirements_mapping as mapping


NORMATIVE = re.compile(r"\b(MUST NOT|SHOULD NOT|MUST|SHOULD|MAY)\b")


def normative_sections(entry: dict) -> list[dict]:
    path = lib.ROOT / "rfc" / f"rfc{entry['number']}.txt"
    result = []
    for section, section_text in lib.rfc_sections(path).items():
        matches = NORMATIVE.findall(section_text)
        if not matches:
            continue
        counts = Counter(matches)
        result.append(
            {
                "occurrences": {
                    key: counts[key] for key in sorted(counts)
                },
                "section": section,
                "section_sha256": lib.section_hash(section_text),
            }
        )
    return result


def surface_assignments(
    scope: dict,
    register: dict,
    requirement_map: dict[str, dict],
    surface_domains: set[str],
    versions: set[str] | None = None,
) -> list[dict]:
    exclusions = {
        item["id"]: item for item in scope["surface_exclusion"]
    }
    if len(exclusions) != len(scope["surface_exclusion"]):
        lib.fail("domain scope has duplicate surface exclusions")
    deferred_groups = {}
    for item in scope.get("surface_defer_group", []):
        if set(item) != {"deferred_to", "domain", "owner", "rationale"}:
            lib.fail("domain scope has malformed deferred surface group")
        if (
            (versions is not None and item["deferred_to"] not in versions)
            or not isinstance(item["rationale"], str)
            or len(item["rationale"].strip()) < 40
        ):
            lib.fail("domain scope has invalid deferred surface group")
        key = (item["domain"], item["owner"])
        if key in deferred_groups:
            lib.fail("domain scope has duplicate deferred surface group")
        deferred_groups[key] = item
    groups = {}
    for item in scope["surface_group"]:
        fields = set(item)
        if fields not in (
            {"domain", "owner", "requirement_id"},
            {"disposition", "domain", "owner", "requirement_id"},
        ):
            lib.fail("domain scope has malformed surface group")
        key = (
            item["domain"],
            item["owner"],
            item.get("disposition"),
        )
        if key in groups:
            lib.fail("domain scope has duplicate surface group")
        requirement = requirement_map.get(item["requirement_id"])
        allowed_domains = (
            mapping.DOMAIN_SURFACES.get(requirement["domain"], set())
            if requirement is not None
            else set()
        )
        if requirement is None or item["domain"] not in allowed_domains:
            lib.fail("domain surface group references wrong requirement")
        if requirement["owner"] != item["owner"]:
            lib.fail("domain surface group owner conflicts with requirement")
        disposition = item.get("disposition")
        allowed = mapping.EXPECTED_DISPOSITIONS[requirement["lifecycle"]]
        if disposition is not None and disposition not in allowed:
            lib.fail("domain surface group disposition conflicts with requirement")
        groups[key] = item["requirement_id"]
    generic = {(domain, owner) for domain, owner, disposition in groups if disposition is None}
    specific = {(domain, owner) for domain, owner, disposition in groups if disposition is not None}
    if generic & specific or generic & set(deferred_groups) or specific & set(deferred_groups):
        lib.fail("domain scope has overlapping surface groups")
    selected = [
        item
        for item in register["surfaces"]
        if item["domain"] in surface_domains
    ]
    result = []
    used_deferred_groups = set()
    for item in selected:
        automatic_id = (
            item.get("requirement_id")
            if scope.get("surface_auto_requirements") is True
            else None
        )
        if automatic_id is not None:
            requirement = requirement_map.get(automatic_id)
            if (
                requirement is None
                or requirement["owner"] != item["owner"]
                or item["domain"]
                not in mapping.DOMAIN_SURFACES.get(requirement["domain"], set())
                or item["disposition"]
                not in mapping.EXPECTED_DISPOSITIONS[
                    requirement["lifecycle"]
                ]
            ):
                lib.fail(f"invalid automatic surface requirement: {item['id']}")
            result.append(
                {
                    "coverage": "requirement",
                    "disposition": item["disposition"],
                    "domain": item["domain"],
                    "id": item["id"],
                    "owner": item["owner"],
                    "requirement_id": automatic_id,
                }
            )
            continue
        excluded = exclusions.get(item["id"])
        if excluded is not None:
            if set(excluded) != {"deferred_to", "id", "rationale"}:
                lib.fail("domain scope has malformed surface exclusion")
            if (
                versions is not None
                and excluded["deferred_to"] not in versions
                or not isinstance(excluded["rationale"], str)
                or len(excluded["rationale"].strip()) < 40
            ):
                lib.fail("domain scope has invalid surface exclusion")
            result.append(
                {
                    "coverage": "deferred",
                    "deferred_to": excluded["deferred_to"],
                    "disposition": item["disposition"],
                    "domain": item["domain"],
                    "id": item["id"],
                    "owner": item["owner"],
                    "rationale": excluded["rationale"],
                }
            )
            continue
        deferred_group = deferred_groups.get((item["domain"], item["owner"]))
        if deferred_group is not None:
            used_deferred_groups.add((item["domain"], item["owner"]))
            result.append(
                {
                    "coverage": "deferred",
                    "deferred_to": deferred_group["deferred_to"],
                    "disposition": item["disposition"],
                    "domain": item["domain"],
                    "id": item["id"],
                    "owner": item["owner"],
                    "rationale": deferred_group["rationale"],
                }
            )
            continue
        requirement_id = groups.get(
            (item["domain"], item["owner"], item["disposition"])
        )
        if requirement_id is None:
            requirement_id = groups.get(
                (item["domain"], item["owner"], None)
            )
        if requirement_id is None:
            lib.fail(f"uncovered domain surface: {item['id']}")
        result.append(
            {
                "coverage": "requirement",
                "disposition": item["disposition"],
                "domain": item["domain"],
                "id": item["id"],
                "owner": item["owner"],
                "requirement_id": requirement_id,
            }
        )
    unused = set(exclusions) - {item["id"] for item in selected}
    if unused:
        lib.fail(f"domain scope has stale surface exclusions: {sorted(unused)}")
    stale_groups = set(deferred_groups) - used_deferred_groups
    if stale_groups:
        lib.fail(f"domain scope has stale deferred groups: {sorted(stale_groups)}")
    return result
