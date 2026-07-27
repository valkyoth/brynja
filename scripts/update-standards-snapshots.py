#!/usr/bin/env python3
"""Refresh reviewed RFC, errata, and IANA evidence from official sources."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import standards_lib as lib


def collect() -> dict[Path, bytes]:
    policy = lib.read_policy()
    rfc_sources = lib.read_source_file(lib.RFC_SOURCES, int)
    numbers = set(rfc_sources)
    index_data = lib.fetch(
        policy["review"]["rfc_index"],
        max_bytes=lib.MAX_RFC_INDEX_BYTES,
    )
    index = lib.project_rfc_index(index_data, numbers)
    index_artifact = lib.json_bytes(index)
    lib.verify_sha256(
        index_artifact,
        policy["review"]["rfc_index_sha256"],
        "RFC index projection",
    )
    artifacts = {lib.RFC_INDEX: index_artifact}

    for registry in policy["registry"]:
        data = lib.fetch(registry["url"], max_bytes=lib.MAX_IANA_BYTES)
        lib.verify_sha256(
            data,
            registry["expected_sha256"],
            f"IANA registry {registry['id']}",
        )
        lib.validate_iana_snapshot(data, registry["id"])
        artifacts[lib.IANA_DIRECTORY / f"{registry['id']}.xml"] = data

    def get_errata(number: int) -> tuple[int, list[dict]]:
        data = lib.fetch(
            lib.errata_url(number),
            max_bytes=lib.MAX_ERRATA_BYTES,
        )
        return number, lib.parse_errata(data, number)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = dict(pool.map(get_errata, sorted(numbers)))
    official_errata = lib.official_errata_bytes(
        results,
        policy["review"]["errata"],
        numbers,
    )
    lib.verify_sha256(
        official_errata,
        policy["review"]["errata_sha256"],
        "RFC errata set",
    )

    reviewed = []
    for number in sorted(numbers):
        for record in results[number]:
            disposition, rationale = lib.errata_disposition(record["status"])
            implementation, security = lib.errata_review(record, policy)
            reviewed.append(
                {
                    **record,
                    "disposition": disposition,
                    "implementation": implementation,
                    "rationale": rationale,
                    "security": security,
                }
            )
    errata = {
        "checked_at": policy["review"]["checked_at"],
        "schema": 1,
        "source": policy["review"]["errata"],
        "reviewed_rfcs": sorted(numbers),
        "records": reviewed,
    }
    artifacts[lib.ERRATA] = lib.json_bytes(errata)

    hashes = []
    for path, data in sorted(
        artifacts.items(),
        key=lambda item: item[0].relative_to(lib.ROOT).as_posix(),
    ):
        name = path.relative_to(lib.ROOT / "standards").as_posix()
        hashes.append(f"{lib.sha256(data)}  {name}")
    artifacts[lib.STANDARDS_HASHES] = ("\n".join(hashes) + "\n").encode()
    return artifacts


def compare(artifacts: dict[Path, bytes]) -> None:
    failures = []
    for path, expected in artifacts.items():
        if not path.is_file():
            failures.append(f"missing: {path.relative_to(lib.ROOT)}")
        elif path.read_bytes() != expected:
            failures.append(f"drift: {path.relative_to(lib.ROOT)}")
    if failures:
        raise RuntimeError(
            "official standards evidence changed; review and run "
            "scripts/update-standards-snapshots.py --write:\n"
            + "\n".join(failures)
        )


def write(artifacts: dict[Path, bytes]) -> None:
    for path, data in artifacts.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail on live drift")
    mode.add_argument("--write", action="store_true", help="replace snapshots")
    args = parser.parse_args()
    artifacts = collect()
    if args.check:
        compare(artifacts)
        print("official RFC, errata, and IANA evidence matches snapshots")
    else:
        write(artifacts)
        print(f"wrote {len(artifacts) - 1} standards evidence artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
