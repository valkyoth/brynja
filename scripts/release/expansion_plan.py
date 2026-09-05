"""Bind the five-part expansion to complete, dependency-ordered public APIs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import roadmap_schedule

REGISTER = Path(__file__).resolve().parents[2] / "docs/ROADMAP_EXPANSION_REGISTER.json"
REGISTER_SHA256 = "f780d1e58207e4b1446f81d40f03e4137fa1562583c712fbc372648d8a285aeb"
DOMAINS = {"crypto", "legacy", "research", "password", "utility", "format", "protocol"}


def read():
    return json.loads(REGISTER.read_text(encoding="utf-8"))


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode()).hexdigest()


def validate(entries, data=None, schedule=None):
    data = read() if data is None else data
    schedule = roadmap_schedule.read() if schedule is None else schedule
    if data["schema"] != 1 or data["groups"] != [1, 2, 3, 4, 5]:
        raise ValueError("expansion groups or schema changed")
    families = data["families"]
    if len(families) != 126 or len({f["name"] for f in families}) != 126:
        raise ValueError("missing or duplicate expansion family")
    positions = {v.removeprefix("v"): i for i, (v, _, _) in enumerate(entries)}
    scopes = {v.removeprefix("v"): (t, s) for v, t, s in entries}
    scheduled = {r["version"]: r for r in schedule["milestones"]}
    owned = set()
    protocol_start = positions[data["first_large_protocol"]]
    for family in families:
        if family["group"] not in data["groups"] or family["domain"] not in DOMAINS:
            raise ValueError("expansion family lost its domain or finding group")
        for field in ("name", "package", "authority", "operations", "tests", "requires"):
            if not family[field]:
                raise ValueError(f"expansion family lost {field}")
        if family["domain"] in {"legacy", "research"}:
            if not family["package"].startswith("brynja-" + family["domain"] + "-"):
                raise ValueError("legacy/research expansion owner escaped isolation")
        milestones = family["milestones"]
        stages = [m["stage"] for m in milestones]
        if stages != (["admission"] + ["implementation"] * len(family["operations"])
                      + ["lifecycle", "portable-acceptance", "final-acceptance"]):
            raise ValueError("expansion operation or acceptance stage missing/reordered")
        versions = [m["version"] for m in milestones]
        indices = [positions.get(v, -1) for v in versions]
        if -1 in indices or indices != sorted(set(indices)) or len(versions) > 12:
            raise ValueError("expansion family order or review size changed")
        if owned.intersection(versions):
            raise ValueError("duplicate expansion milestone owner")
        owned.update(versions)
        if family["domain"] == "protocol":
            if indices[0] < protocol_start:
                raise ValueError("large protocol moved before its reserved late phase")
        elif indices[-1] >= protocol_start:
            raise ValueError("primitive/format prerequisite follows the large protocols")
        for i, milestone in enumerate(milestones):
            version = milestone["version"]
            title, scope = scopes[version]
            if title != milestone["title"] or hashlib.sha256(scope.encode()).hexdigest() != milestone["scope_sha256"]:
                raise ValueError("expansion title or reviewed scope drift")
            expected = set(family["requires"] if i == 0 else [versions[i - 1]])
            if set(scheduled[version]["requires"]) != expected:
                raise ValueError("expansion schedule and prerequisite contract differ")
            if any(d not in positions or positions[d] >= positions[version] for d in expected):
                raise ValueError("expansion consumer precedes an executable prerequisite")
            if 0 < i <= len(family["operations"]):
                if family["operations"][i - 1] not in scope:
                    raise ValueError("expansion operation is absent from implementation")
        if family["authority"] not in scopes[versions[0]][1]:
            raise ValueError("expansion authority is absent from admission")
        if family["tests"] not in scopes[versions[-2]][1]:
            raise ValueError("expansion acceptance lost its specific test contract")
    expected_owned = {v for v in positions if v.startswith("0.") and
        (351 <= int(v.split(".")[1]) <= 474 or
         v in {f"0.24.{i}" for i in range(24, 30)} or
         v in {f"0.100.{i}" for i in range(1, 7)})}
    if owned != expected_owned:
        raise ValueError("expansion contains unowned or missing milestones")
    integrated = scheduled[data["final_integration"]]
    if set(integrated["requires"]) != {f["milestones"][-1]["version"] for f in families}:
        raise ValueError("integrated closure omitted a family acceptance")
    if positions[data["final_integration"]] >= positions[data["final_candidate_gate"]]:
        raise ValueError("candidate freeze precedes integrated expansion")
    if digest(data) != REGISTER_SHA256:
        raise ValueError("reviewed expansion inventory changed without review")
