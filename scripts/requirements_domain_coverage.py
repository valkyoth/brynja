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
) -> list[dict]:
    exclusions = {
        item["id"]: item for item in scope["surface_exclusion"]
    }
    if len(exclusions) != len(scope["surface_exclusion"]):
        lib.fail("domain scope has duplicate surface exclusions")
    groups = {}
    for item in scope["surface_group"]:
        if set(item) != {"domain", "owner", "requirement_id"}:
            lib.fail("domain scope has malformed surface group")
        key = (item["domain"], item["owner"])
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
        groups[key] = item["requirement_id"]
    selected = [
        item
        for item in register["surfaces"]
        if item["domain"] in surface_domains
    ]
    result = []
    for item in selected:
        excluded = exclusions.get(item["id"])
        if excluded is not None:
            if set(excluded) != {"deferred_to", "id", "rationale"}:
                lib.fail("domain scope has malformed surface exclusion")
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
        requirement_id = groups.get((item["domain"], item["owner"]))
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
    return result
