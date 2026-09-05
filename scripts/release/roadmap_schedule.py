"""Validate stable milestone identities, reviewed dependencies and release order."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

PATH = Path(__file__).resolve().parents[2] / "requirements/roadmap-schedule.json"


def read():
    return json.loads(PATH.read_text(encoding="utf-8"))


def key(version):
    if version == "1.0.0-rc.1":
        return (1, 0, 0, 0)
    if version == "1.0.0":
        return (1, 0, 0, 1)
    if not re.fullmatch(r"0\.[0-9]+\.[0-9]+", version):
        raise ValueError("invalid roadmap version")
    return (*map(int, version.split(".")), 0)


def graph_hash(data):
    ids = {r["version"]: r["id"] for r in data["milestones"]}
    edges = sorted((r["id"], sorted(ids.get(v, "MISSING:" + v) for v in r["requires"]))
                   for r in data["milestones"])
    return hashlib.sha256(json.dumps(edges, separators=(",", ":")).encode()).hexdigest()


def expected_versions():
    data = read()
    validate_manifest(data)
    return ["v" + r["version"] for r in data["milestones"]]


def validate_manifest(data):
    if data["schema"] != 1 or data["immutable_through"] != "0.24.16":
        raise ValueError("roadmap schedule schema or immutable boundary drift")
    records = data["milestones"]
    versions = [r["version"] for r in records]
    if len(records) != 2004 or len(set(versions)) != len(records):
        raise ValueError("missing or duplicate scheduled milestone")
    if len({r["id"] for r in records}) != len(records):
        raise ValueError("duplicate stable milestone identity")
    if versions != sorted(versions, key=key):
        raise ValueError("roadmap version order is not monotonic")
    minors = {}
    positions = {v: i for i, v in enumerate(versions)}
    for record in records:
        version = record["version"]
        if version.startswith("0."):
            _, minor, patch = map(int, version.split("."))
            minors.setdefault(minor, []).append(patch)
            if minor <= 24 and record["id"] != version:
                raise ValueError("released or in-progress milestone renumbered")
        for required in record["requires"]:
            if required not in positions or positions[required] >= positions[version]:
                raise ValueError("executable prerequisite missing or scheduled after consumer")
        if len(set(record["requires"])) != len(record["requires"]):
            raise ValueError("duplicate prerequisite")
    if list(minors) != list(range(1, 481)):
        raise ValueError("unexplained minor-version gap")
    for minor, patches in minors.items():
        if patches != list(range(len(patches))):
            raise ValueError("unexplained patch-version gap")
        if minor >= 25 and len(patches) > 12:
            raise ValueError("future family needs separate minor versions")
    if graph_hash(data) != data["audited_graph_sha256"]:
        raise ValueError("audited prerequisite graph changed without review")


def validate(entries, data=None):
    data = read() if data is None else data
    validate_manifest(data)
    records = data["milestones"]
    if len(entries) != len(records):
        raise ValueError("schedule and plan counts differ")
    positions = {r["version"]: i for i, r in enumerate(records)}
    actual_forward = []
    for (version, title, scope), record in zip(entries, records, strict=True):
        if (version, title) != ("v" + record["version"], record["title"]):
            raise ValueError("plan lost a stable scheduled capability or changed its order")
        digest = hashlib.sha256(scope.encode()).hexdigest()
        if digest != record["scope_sha256"]:
            raise ValueError("plan scope differs from dependency-reviewed schedule")
        for target in sorted(set(re.findall(r"v(0\.[0-9]+\.[0-9]+)", scope))):
            if target not in positions:
                raise ValueError("plan references an absent numbered milestone")
            if positions[target] > positions[record["version"]]:
                actual_forward.append((record["version"], target, digest))
    expected_forward = [(r["version"], r["target"], r["scope_sha256"])
                        for r in data["forward_references"]]
    if actual_forward != expected_forward or any(not r["disposition"] for r in data["forward_references"]):
        raise ValueError("unreviewed forward execution or structural-reference drift")
