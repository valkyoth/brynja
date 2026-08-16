#!/usr/bin/env python3
"""Coverage artifact assembly for normative-domain requirement bundles."""

from __future__ import annotations

import requirements_domain_coverage as domain_coverage


def authority_records(
    authorities: dict[str, dict],
    requirements: list[dict],
    section_coverage: dict[tuple[str, str], dict],
) -> list[dict]:
    records = []
    for identifier, entry in sorted(authorities.items()):
        record = {
            "authority_role": entry.get("lifecycle", "current"),
            "domains": entry["domains"],
            "id": identifier,
            "milestones": entry["milestones"],
            "requirement_ids": sorted(
                requirement["id"]
                for requirement in requirements
                if identifier
                in {source["id"] for source in requirement["sources"]}
            ),
            "sha256": entry["sha256"],
        }
        if "number" in entry:
            normative = domain_coverage.normative_sections(entry)
            for section in normative:
                section.update(
                    section_coverage.get(
                        (identifier, section["section"]), {}
                    )
                )
            record["normative_sections"] = normative
            record["status"] = entry["status"]
        else:
            record["role"] = entry["role"]
        records.append(record)
    return records


def build(
    config,
    scope: dict,
    authorities: dict[str, dict],
    authority_deferrals: list[dict],
    owner_milestones: set[str],
    register: dict,
    requirements: list[dict],
    requirement_map: dict[str, dict],
    section_coverage: dict[tuple[str, str], dict],
    versions: set[str],
    policy_hash: str,
) -> dict:
    records = authority_records(
        authorities, requirements, section_coverage
    )
    normative = [
        section
        for record in records
        for section in record.get("normative_sections", [])
    ]
    assigned_surfaces = domain_coverage.surface_assignments(
        scope,
        register,
        requirement_map,
        set(config.surface_domains),
        versions,
    )
    coverage = {
        "authorities": records,
        "authority_count": len(records),
        "excluded_normative_section_count": sum(
            "disposition" in section for section in normative
        ),
        "mapped_normative_section_count": sum(
            bool(section.get("requirement_ids")) for section in normative
        ),
        "normative_section_count": len(normative),
        "policy_sha256": policy_hash,
        "requirement_count": len(requirements),
        "schema": 1,
        "surface_count": len(assigned_surfaces),
        "surfaces": assigned_surfaces,
    }
    if (
        authority_deferrals
        or owner_milestones
        or scope.get("surface_defer_group")
    ):
        coverage.update(
            {
                "authority_deferrals": authority_deferrals,
                "deferred_authority_count": len(authority_deferrals),
                "owner_milestone_count": len(owner_milestones),
                "owner_milestones": sorted(owner_milestones),
                "schema": 2,
            }
        )
    return coverage
