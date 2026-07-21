#!/usr/bin/env python3
"""Enforce Brynja workspace dependency and publication boundaries."""

from __future__ import annotations

import json
import sys
from pathlib import Path


HISTORICAL = {
    "brynja-historical",
    "brynja-pct",
    "brynja-snp",
    "brynja-ssl1-research",
    "brynja-ssl2",
    "brynja-ssl3",
    "brynja-tls10",
    "brynja-tls11",
    "brynja-wtls",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate-workspace-metadata.py METADATA", file=sys.stderr)
        return 2
    document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    packages = {package["id"]: package for package in document["packages"]}
    names = {package["name"]: package_id for package_id, package in packages.items()}

    for package in packages.values():
        if package.get("source") is not None:
            raise ValueError(f"external package source: {package['name']}")
        if package.get("publish") != []:
            raise ValueError(f"foundation package is publishable: {package['name']}")
        for dependency in package["dependencies"]:
            if dependency.get("source") is not None:
                raise ValueError(
                    f"external dependency: {package['name']} -> {dependency['name']}"
                )

    resolve = document.get("resolve")
    if not isinstance(resolve, dict):
        raise ValueError("Cargo metadata is missing the resolved graph")
    edges = {
        node["id"]: {dependency["pkg"] for dependency in node["deps"]}
        for node in resolve["nodes"]
    }
    pending = [names["brynja"]]
    seen: set[str] = set()
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        pending.extend(edges.get(package_id, set()))
    leaked = sorted(packages[package_id]["name"] for package_id in seen if packages[package_id]["name"] in HISTORICAL)
    if leaked:
        raise ValueError(f"modern facade reaches historical packages: {leaked}")
    print("workspace has zero external dependencies and preserves protocol isolation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

