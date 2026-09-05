#!/usr/bin/env python3
"""Regression fixtures for complete roadmap prerequisite ordering."""
import copy
import importlib.util
from pathlib import Path

import roadmap_schedule as schedule


def main():
    spec = importlib.util.spec_from_file_location("plan", Path(__file__).with_name("check-release-plan.py"))
    plan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plan)
    entries = plan.version_entries(Path("docs/VERSION_PLAN.md"))
    data = schedule.read()
    schedule.validate(entries, data)
    cases = 0

    def reject(candidate, rows=entries):
        nonlocal cases
        try:
            schedule.validate(rows, candidate)
        except ValueError:
            cases += 1
            return
        raise AssertionError("roadmap schedule accepted a regression")

    for index, record in enumerate(data["milestones"]):
        for dependency in record["requires"]:
            changed = copy.deepcopy(data)
            changed["milestones"][index]["requires"].remove(dependency)
            reject(changed)
        if record["requires"]:
            changed = copy.deepcopy(data)
            changed["milestones"][index]["requires"] = [record["version"]]
            reject(changed)
    for i, ref in enumerate(data["forward_references"]):
        changed = copy.deepcopy(data)
        changed["forward_references"][i]["disposition"] = ""
        reject(changed)
    changed = copy.deepcopy(data)
    changed["milestones"][0]["id"] = "rewritten-tag"
    reject(changed)
    changed = copy.deepcopy(data)
    changed["milestones"].pop()
    reject(changed)
    reject(data, entries[:-1])
    v,t,s = entries[-3]
    reject(data, entries[:-3]+[(v,t,s+" omitted prerequisite")]+entries[-2:])
    print(f"roadmap schedule rejects {cases} dependency, forward-reference and identity regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
