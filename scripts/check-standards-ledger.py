#!/usr/bin/env python3
"""Validate and deterministically generate Brynja's standards source ledger."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

import standards_lib as lib


def fail(message: str) -> None:
    raise RuntimeError(message)


def check_hashes(
    manifest: dict[str, str],
    directory: Path,
    expected: set[str],
    label: str,
    *,
    verify_files: bool = True,
) -> None:
    if set(manifest) != expected:
        fail(
            f"{label} checksum set differs: expected {sorted(expected)}, "
            f"found {sorted(manifest)}"
        )
    for name, digest in manifest.items():
        if lib.SHA256_PATTERN.fullmatch(digest) is None:
            fail(f"{label} has invalid SHA-256 pin: {name}")
        if not verify_files:
            continue
        path = directory / name
        if not path.is_file():
            fail(f"{label} pinned file is missing: {name}")
        if lib.sha256(path.read_bytes()) != digest:
            fail(f"{label} checksum mismatch: {name}")


def roadmap_versions() -> set[str]:
    text = (lib.ROOT / "docs/VERSION_PLAN.md").read_text(encoding="utf-8")
    return set(re.findall(r"`(H?\d+\.\d+(?:\.\d+)?)`", text))


def validate_policy(policy: dict, rfcs: dict, local: dict) -> None:
    if policy.get("schema") != {"version": 1}:
        fail("source policy schema must be exactly version 1")
    domains = policy.get("domain", [])
    domain_ids = [domain["id"] for domain in domains]
    if len(domain_ids) != len(set(domain_ids)):
        fail("source policy has duplicate domain IDs")
    registry_ids = [item["id"] for item in policy.get("registry", [])]
    if len(registry_ids) != len(set(registry_ids)):
        fail("source policy has duplicate registry IDs")
    review = policy.get("review", {})
    if not review.get("pin_provenance", "").strip():
        fail("source policy requires independent pin provenance")
    expected_review_urls = {
        "rfc_index": "https://www.rfc-editor.org/rfc-index.xml",
        "errata": "https://errata.rfc-editor.org/search/",
    }
    for field, expected in expected_review_urls.items():
        if review.get(field) != expected:
            fail(f"source policy {field} URL is not allowlisted")
        lib.validate_https_url(review[field])
        digest = review.get(f"{field}_sha256")
        if not isinstance(digest, str) or lib.SHA256_PATTERN.fullmatch(digest) is None:
            fail(f"source policy {field} requires a pinned SHA-256")

    for number, source in rfcs.items():
        expected = f"https://www.rfc-editor.org/rfc/rfc{number}.txt"
        if source["url"] != expected:
            fail(f"RFC {number} URL is not allowlisted")
    itu_sources = {
        "ITU-T.X.690-202102.pdf": (
            "https://www.itu.int/rec/dologin_pub.asp?"
            "id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items"
        ),
        "ITU-T.X.690-202109-Err1.pdf": (
            "https://www.itu.int/rec/dologin_pub.asp?"
            "id=T-REC-X.690-202109-I%21Err1%21PDF-E&lang=e&type=items"
        ),
    }
    riscv_sources = {
        "RISCV.Crypto.Scalar-1.0.1.pdf": (
            "https://docs.riscv.org/reference/isa/extensions/crypto-scalar/"
            "_attachments/riscv-crypto-spec-scalar.pdf"
        ),
        "RISCV.Crypto.Vector-1.0.pdf": (
            "https://docs.riscv.org/reference/isa/extensions/crypto-vector/"
            "_attachments/riscv-crypto-spec-vector.pdf"
        ),
    }
    for name, source in local.items():
        url = source["url"]
        allowed = (
            url.startswith("https://nvlpubs.nist.gov/")
            or (name in itu_sources and url == itu_sources[name])
            or (name in riscv_sources and url == riscv_sources[name])
        )
        if "/" in name or not allowed:
            fail(f"local authority {name} URL is not allowlisted")

    rfc_domains, local_domains = lib.domain_maps(policy)
    if set(rfc_domains) != set(rfcs):
        fail("domain map must cover exactly every locked RFC")
    if set(local_domains) != set(local):
        fail("domain map must cover exactly every locked local source")

    lifecycle_seen = {}
    for name, numbers in policy["lifecycle"].items():
        for number in numbers:
            if number not in rfcs:
                fail(f"lifecycle {name} references unlocked RFC {number}")
            if number in lifecycle_seen:
                fail(f"RFC {number} has multiple lifecycle classifications")
            lifecycle_seen[number] = name

    versions = roadmap_versions()
    milestone_refs = {
        milestone
        for domain in domains
        for milestone in domain["milestones"]
    }
    milestone_refs.update(
        milestone
        for registry in policy["registry"]
        for milestone in registry["milestones"]
    )
    milestone_refs.update(blocker["owner"] for blocker in policy["blocker"])
    if milestone_refs - versions:
        fail(f"unknown roadmap milestones: {sorted(milestone_refs - versions)}")

    for registry in policy["registry"]:
        unknown = set(registry["domains"]) - set(domain_ids)
        if unknown:
            fail(f"registry {registry['id']} has unknown domains: {sorted(unknown)}")
        expected_url = (
            f"https://www.iana.org/assignments/{registry['id']}/"
            f"{registry['id']}.xml"
        )
        if registry["url"] != expected_url:
            fail(f"registry {registry['id']} URL is not allowlisted")
        lib.validate_https_url(registry["url"])
        digest = registry.get("expected_sha256")
        if not isinstance(digest, str) or lib.SHA256_PATTERN.fullmatch(digest) is None:
            fail(f"registry {registry['id']} requires a pinned SHA-256")

    blocker_ids = [blocker["id"] for blocker in policy["blocker"]]
    if blocker_ids != ["ecdhe-ml-kem-groups"]:
        fail("the final ECDHE-ML-KEM admission blocker is required")
    blocker = policy["blocker"][0]
    required = {
        "status": "resolved",
        "required_registry": "tls-parameters",
        "required_final_rfc": True,
        "required_final_iana_codepoints": True,
        "drafts_forbidden": True,
    }
    for key, value in required.items():
        if blocker.get(key) != value:
            fail(f"ECDHE-ML-KEM resolution record requires {key}={value!r}")
    if 10024 not in rfcs:
        fail("ECDHE-ML-KEM resolution requires locked RFC 10024")


def validate_closure(policy: dict, index: dict, locked: set[int]) -> None:
    actual = set()
    for number_text, entry in index["rfcs"].items():
        number = int(number_text)
        for relation, field in (
            ("updated-by", "updated_by"),
            ("obsoleted-by", "obsoleted_by"),
        ):
            actual.update(
                (number, relation, target)
                for target in entry[field]
                if target not in locked
            )
        if lib.lifecycle_for(number, policy) == "current" and entry["obsoleted_by"]:
            fail(f"current RFC {number} is obsoleted")

    exclusions = {
        (item["source"], item["relation"], item["target"])
        for item in policy["closure_exclusion"]
    }
    if len(exclusions) != len(policy["closure_exclusion"]):
        fail("closure exclusions must be unique")
    if exclusions != actual:
        fail(
            "RFC updated-by/obsoleted-by closure differs: "
            f"missing={sorted(actual - exclusions)}, "
            f"stale={sorted(exclusions - actual)}"
        )
    for item in policy["closure_exclusion"]:
        if not item["reason"].strip():
            fail("every RFC closure exclusion requires a reason")


def validate_errata(
    errata: dict,
    locked: set[int],
    policy: dict,
) -> dict[int, list[dict]]:
    if errata.get("schema") != 1 or set(errata.get("reviewed_rfcs", [])) != locked:
        fail("errata review must cover exactly every locked RFC")
    if errata.get("source") != policy["review"]["errata"]:
        fail("errata review source is not allowlisted")
    if errata.get("checked_at") != policy["review"]["checked_at"]:
        fail("errata review date must match the source policy")
    records: dict[int, list[dict]] = {number: [] for number in locked}
    seen = set()
    for record in errata.get("records", []):
        required = {
            "date_reported",
            "disposition",
            "id",
            "implementation",
            "rationale",
            "rfc",
            "section",
            "security",
            "status",
            "type",
            "url",
        }
        if set(record) != required:
            fail(f"erratum record {record.get('id')} has unexpected fields")
        if record["id"] in seen or record["rfc"] not in locked:
            fail(f"duplicate or unlocked erratum {record['id']}")
        seen.add(record["id"])
        disposition, rationale = lib.errata_disposition(record["status"])
        if (record["disposition"], record["rationale"]) != (
            disposition,
            rationale,
        ):
            fail(f"erratum {record['id']} has an invalid reviewed decision")
        implementation, security = lib.errata_review(record, policy)
        if (record["implementation"], record["security"]) != (
            implementation,
            security,
        ):
            fail(f"erratum {record['id']} has invalid implementation or security review")
        if record["type"] not in {"Technical", "Editorial"}:
            fail(f"erratum {record['id']} has an invalid type")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", record["date_reported"]):
            fail(f"erratum {record['id']} has an invalid report date")
        expected_url = f"https://errata.rfc-editor.org/eid{record['id']}/"
        if record["url"] != expected_url:
            fail(f"erratum {record['id']} has a non-authoritative URL")
        records[record["rfc"]].append(record)
    official = lib.official_errata_bytes(
        records,
        errata["source"],
        locked,
    )
    lib.verify_sha256(
        official,
        policy["review"]["errata_sha256"],
        "RFC errata set",
    )
    return records


def build_ledger() -> dict:
    policy = lib.read_policy()
    rfc_sources = lib.read_source_file(lib.RFC_SOURCES, int)
    local_sources = lib.read_source_file(lib.LOCAL_SOURCES)
    validate_policy(policy, rfc_sources, local_sources)

    rfc_hashes = lib.read_hash_file(lib.RFC_HASHES)
    expected_rfc_files = {f"rfc{number}.txt" for number in rfc_sources}
    check_hashes(rfc_hashes, lib.ROOT / "rfc", expected_rfc_files, "RFC")
    local_hashes = lib.read_hash_file(lib.LOCAL_HASHES)
    local_directory = lib.ROOT / "references/local"
    local_mode = os.environ.get("VERIFY_LOCAL_REFERENCE_FILES", "0")
    if local_mode not in {"0", "1"}:
        fail("VERIFY_LOCAL_REFERENCE_FILES must be 0 or 1")
    local_files_present = any(
        (local_directory / name).is_file() for name in local_sources
    )
    check_hashes(
        local_hashes,
        local_directory,
        set(local_sources),
        "local authority",
        verify_files=local_mode == "1" or local_files_present,
    )

    standards_hashes = lib.read_hash_file(lib.STANDARDS_HASHES)
    expected_standards = {"ERRATA.json", "snapshots/rfc-index.json"}
    expected_standards.update(
        f"snapshots/iana/{registry['id']}.xml"
        for registry in policy["registry"]
    )
    check_hashes(
        standards_hashes,
        lib.ROOT / "standards",
        expected_standards,
        "standards evidence",
    )

    index = json.loads(lib.RFC_INDEX.read_text(encoding="utf-8"))
    if index.get("schema") != 1 or set(map(int, index.get("rfcs", {}))) != set(
        rfc_sources
    ):
        fail("RFC index projection must contain exactly every locked RFC")
    validate_closure(policy, index, set(rfc_sources))

    errata = json.loads(lib.ERRATA.read_text(encoding="utf-8"))
    errata_by_rfc = validate_errata(errata, set(rfc_sources), policy)
    rfc_domains, local_domains = lib.domain_maps(policy)

    rfc_entries = []
    for number, source in sorted(rfc_sources.items()):
        domains = sorted(rfc_domains[number])
        metadata = index["rfcs"][str(number)]
        rfc_entries.append(
            {
                "domains": domains,
                "errata": [
                    {
                        "disposition": record["disposition"],
                        "id": record["id"],
                        "status": record["status"],
                    }
                    for record in errata_by_rfc[number]
                ],
                "lifecycle": lib.lifecycle_for(number, policy),
                "milestones": lib.milestones_for(domains, policy),
                "number": number,
                "relationships": {
                    key: metadata[key]
                    for key in (
                        "obsoleted_by",
                        "obsoletes",
                        "updated_by",
                        "updates",
                    )
                },
                "role": source["role"],
                "sha256": rfc_hashes[f"rfc{number}.txt"],
                "status": metadata["current_status"],
                "title": metadata["title"],
                "url": source["url"],
            }
        )

    local_entries = []
    for name, source in sorted(local_sources.items()):
        domains = sorted(local_domains[name])
        local_entries.append(
            {
                "domains": domains,
                "filename": name,
                "milestones": lib.milestones_for(domains, policy),
                "role": source["role"],
                "sha256": local_hashes[name],
                "url": source["url"],
            }
        )

    registries = []
    for registry in policy["registry"]:
        relative = f"snapshots/iana/{registry['id']}.xml"
        if standards_hashes[relative] != registry["expected_sha256"]:
            fail(f"registry {registry['id']} snapshot differs from its policy pin")
        metadata = lib.validate_iana_snapshot(
            (lib.ROOT / "standards" / relative).read_bytes(),
            registry["id"],
        )
        registries.append(
            {
                **metadata,
                "domains": registry["domains"],
                "id": registry["id"],
                "milestones": registry["milestones"],
                "sha256": standards_hashes[relative],
                "url": registry["url"],
            }
        )

    return {
        "blockers": policy["blocker"],
        "closure_exclusions": policy["closure_exclusion"],
        "integrity": {
            "errata_sha256": policy["review"]["errata_sha256"],
            "local_source_manifest_sha256": lib.sha256(
                lib.LOCAL_HASHES.read_bytes()
            ),
            "pin_provenance": policy["review"]["pin_provenance"],
            "rfc_index_projection_sha256": policy["review"][
                "rfc_index_sha256"
            ],
            "rfc_source_manifest_sha256": lib.sha256(
                lib.RFC_HASHES.read_bytes()
            ),
        },
        "local_authorities": local_entries,
        "registries": registries,
        "rfcs": rfc_entries,
        "schema": 1,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = lib.json_bytes(build_ledger())
    if args.write:
        lib.LEDGER.write_bytes(expected)
        print("wrote standards/source-ledger.json")
    elif not lib.LEDGER.is_file() or lib.LEDGER.read_bytes() != expected:
        fail("standards source ledger is stale; rerun with --write")
    else:
        print("standards source ledger is complete and reproducible")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
