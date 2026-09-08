#!/usr/bin/env python3
"""Exercise policy mutations without changing runtime CPU admission."""

import copy
import importlib.util
from pathlib import Path

import acceleration_plan as acceleration
import roadmap_schedule


def main():
    spec = importlib.util.spec_from_file_location(
        "release_plan", Path(__file__).with_name("check-release-plan.py")
    )
    plan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plan)
    entries = plan.version_entries(Path("docs/VERSION_PLAN.md"))
    release = Path("docs/RELEASE_PLAN.md").read_text(encoding="utf-8")
    version = Path("docs/VERSION_PLAN.md").read_text(encoding="utf-8")
    schedule = roadmap_schedule.read()
    acceleration.validate(entries, release, version, schedule)
    count = 0

    def reject(rows=entries, r=release, v=version, data=schedule):
        nonlocal count
        try:
            acceleration.validate(rows, r, v, data)
        except ValueError:
            count += 1
            return
        raise AssertionError("acceleration plan accepted a regression")

    for rule in acceleration.CONTRACT:
        reject(r=" ".join(release.split()).replace(rule, "omitted", 1))
        reject(v=" ".join(version.split()).replace(rule, "omitted", 1))
    for patch, tokens in acceleration.PROFILES.items():
        target = f"v0.24.{patch}"
        reject(rows=[row for row in entries if row[0] != target])
        for token in tokens:
            reject(rows=[(v, t, s.replace(token, "omitted")) if v == target else (v, t, s)
                         for v, t, s in entries])
        changed = copy.deepcopy(schedule)
        record = next(r for r in changed["milestones"] if r["version"] == target[1:])
        record["requires"] = []
        # Re-signing the graph cannot excuse an explicit prerequisite bypass.
        changed["audited_graph_sha256"] = roadmap_schedule.graph_hash(changed)
        reject(data=changed)
    changed = copy.deepcopy(schedule)
    hmac = next(r for r in changed["milestones"] if r["version"] == "0.25.0")
    hmac["requires"].remove("0.24.54")
    changed["audited_graph_sha256"] = roadmap_schedule.graph_hash(changed)
    reject(data=changed)
    print(f"acceleration usability plan rejects {count} profile, claim and prerequisite regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
