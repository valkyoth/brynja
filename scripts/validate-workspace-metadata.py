#!/usr/bin/env python3
"""Enforce Brynja workspace dependency and publication boundaries."""

from __future__ import annotations

import json
import sys
from pathlib import Path


AMBIGUOUS_HISTORICAL_NAMES = {
    "brynja-pct",
    "brynja-snp",
    "brynja-ssl1-research",
    "brynja-ssl2",
    "brynja-ssl3",
    "brynja-tls10",
    "brynja-tls11",
    "brynja-wtls",
}


def is_historical(name: str) -> bool:
    return name == "brynja-historical" or name.startswith("brynja-historical-")


def reachable_names(
    root: str,
    names: dict[str, str],
    packages: dict[str, dict],
    edges: dict[str, set[str]],
) -> set[str]:
    pending = [names[root]]
    seen: set[str] = set()
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        pending.extend(edges.get(package_id, set()))
    return {packages[package_id]["name"] for package_id in seen}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate-workspace-metadata.py METADATA", file=sys.stderr)
        return 2
    document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    packages = {package["id"]: package for package in document["packages"]}
    names = {package["name"]: package_id for package_id, package in packages.items()}
    ambiguous = sorted(AMBIGUOUS_HISTORICAL_NAMES.intersection(names))
    if ambiguous:
        raise ValueError(f"historical package lacks explicit prefix: {ambiguous}")

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
    modern = reachable_names("brynja", names, packages, edges)
    leaked = sorted(name for name in modern if is_historical(name))
    if leaked:
        raise ValueError(f"modern facade reaches historical packages: {leaked}")

    router = reachable_names("brynja-tls", names, packages, edges)
    required_router = {"brynja-tls", "brynja-tls12", "brynja-tls13"}
    if not required_router.issubset(router):
        raise ValueError("evergreen TLS router does not reach both version engines")
    if "brynja-tls13-handshake" not in router:
        raise ValueError("TLS 1.3 engine does not reach its handshake package")

    quic = reachable_names("brynja-quic-tls", names, packages, edges)
    forbidden_quic = {"brynja-tls", "brynja-tls12", "brynja-tls13"}
    if forbidden_quic.intersection(quic):
        raise ValueError("QUIC reaches stream TLS or its multi-version router")
    if "brynja-tls13-handshake" not in quic:
        raise ValueError("QUIC does not reach the recordless TLS 1.3 handshake")

    print(
        "workspace has zero external dependencies and preserves historical "
        "and version-specific TLS isolation"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
