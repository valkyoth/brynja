#!/usr/bin/env python3
"""Adversarial fixtures for every added family, operation and dependency."""
import copy
import importlib.util
from pathlib import Path

import expansion_plan


def main():
    spec = importlib.util.spec_from_file_location("plan", Path(__file__).with_name("check-release-plan.py"))
    plan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plan)
    entries = plan.version_entries(Path("docs/VERSION_PLAN.md"))
    data = expansion_plan.read()
    expansion_plan.validate(entries, data)
    cases = 0

    def reject(changed, rows=entries, schedule=None):
        nonlocal cases
        try:
            expansion_plan.validate(rows, changed, schedule)
        except ValueError:
            cases += 1
            return
        raise AssertionError("expansion validator accepted a broken contract")

    for i, family in enumerate(data["families"]):
        for field in ("authority", "package", "operations", "tests", "requires"):
            changed = copy.deepcopy(data)
            changed["families"][i][field] = [] if field in {"operations", "requires"} else ""
            reject(changed)
        changed = copy.deepcopy(data)
        changed["families"][i]["milestones"].pop(-2)
        reject(changed)
        changed = copy.deepcopy(data)
        changed["families"][i]["requires"] = ["0.480.0"]
        reject(changed)
        final = family["milestones"][-1]["version"]
        reject(data, [(v, t, s + " omitted operation") if v == "v" + final else (v,t,s) for v,t,s in entries])
        # Test the schedule edge separately from the inventory hash binding.
        schedule = expansion_plan.roadmap_schedule.read()
        record = next(r for r in schedule["milestones"] if r["version"] == final)
        record["requires"] = []
        reject(data, schedule=schedule)
    changed = copy.deepcopy(data)
    changed["families"].pop()
    reject(changed)
    changed = copy.deepcopy(data)
    changed["first_large_protocol"] = "0.475.0"
    reject(changed)
    schedule = expansion_plan.roadmap_schedule.read()
    next(r for r in schedule["milestones"] if r["version"] == "0.475.0")["requires"].pop()
    reject(data, schedule=schedule)
    print(f"five-part expansion covers 126 families and rejects {cases} API/source/order regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
