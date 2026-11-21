#!/usr/bin/env python3
"""Compare SPDX JSON after removing generator nondeterminism."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
import sys
from pathlib import Path


def canonicalize(value: object) -> object:
    if isinstance(value, dict):
        return {key: canonicalize(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        items = [canonicalize(item) for item in value]
        return sorted(items, key=canonical_json)
    return value


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def normalized(path: Path) -> object:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path} must contain a JSON object")
    document.pop("documentNamespace", None)
    creation = document.get("creationInfo")
    if isinstance(creation, dict):
        creation.pop("created", None)
    return canonicalize(document)


def stable_document(path: Path, epoch: str) -> str:
    """Use the same graph as --check; keep substantive checksums and edges."""
    if not epoch.isascii() or not epoch.isdecimal():
        raise ValueError("expected a nonnegative integer source timestamp")
    doc = normalized(path)
    doc["creationInfo"]["created"] = datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for field in ("packages", "files"):
        doc[field].sort(key=lambda item: item["SPDXID"])
    doc["relationships"].sort(key=lambda edge: (edge["spdxElementId"], edge["relationshipType"], edge["relatedSpdxElement"]))
    identity = hashlib.sha256(canonical_json(doc).encode()).hexdigest()
    doc["documentNamespace"] = "https://spdx.org/spdxdocs/brynja-" + identity
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "--prepare":
        path = Path(sys.argv[2])
        path.write_text(stable_document(path, sys.argv[3]), encoding="utf-8")
        return 0
    if len(sys.argv) != 3:
        print("usage: compare_sbom.py EXPECTED GENERATED", file=sys.stderr)
        return 2
    if normalized(Path(sys.argv[1])) != normalized(Path(sys.argv[2])):
        print("SBOM is stale; run scripts/release/generate-sbom.sh --write", file=sys.stderr)
        return 1
    print("committed SBOM matches the current dependency graph")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

