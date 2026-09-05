#!/usr/bin/env python3
"""Adversarial tests for catalogue migration and dependency closure."""
import copy
import importlib.util
import json
from pathlib import Path

import catalogue_plan


def main():
    spec = importlib.util.spec_from_file_location("plan", Path(__file__).with_name("check-release-plan.py"))
    plan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plan)
    entries = plan.version_entries(Path("docs/VERSION_PLAN.md"))
    register = json.loads(catalogue_plan.REGISTER.read_text(encoding="utf-8"))
    catalogue_plan.validate(entries, register)
    cases = 0

    def reject(data, rows=entries):
        nonlocal cases
        try:
            catalogue_plan.validate(rows, data)
        except ValueError:
            cases += 1
            return
        raise AssertionError("catalogue validator accepted a broken fixture")

    for key in ("variants", "package", "domain", "authority", "api_contract", "verification_focus", "requires"):
        data = copy.deepcopy(register)
        data["families"][0][key] = [] if key in ("variants", "requires") else ""
        reject(data)
    for index in range(104):
        data = copy.deepcopy(register)
        data["inventory"][index]["owners"] = ["unassigned"]
        reject(data)
    for family_index, family in enumerate(register["families"]):
        data = copy.deepcopy(register)
        data["families"][family_index]["requires"] = ["0.285.0"]
        reject(data)
        data = copy.deepcopy(register)
        data["families"][family_index]["milestones"] = [m for m in family["milestones"] if m["stage"] != "portable-acceptance"]
        reject(data)
        final = family["milestones"][-1]["version"]
        reject(register, [(v,t,s+" weakened") if v=="v"+final else (v,t,s) for v,t,s in entries])
    data = copy.deepcopy(register)
    data["inventory"].pop()
    reject(data)
    for name in catalogue_plan.PREREQUISITES:
        data = copy.deepcopy(register)
        family = next(f for f in data["families"] if f["name"] == name)
        family["requires"].remove(catalogue_plan.PREREQUISITES[name])
        reject(data)
    for name, predecessor in catalogue_plan.FAMILY_EDGES.items():
        data = copy.deepcopy(register)
        family = next(f for f in data["families"] if f["name"] == name)
        source = next(f for f in data["families"] if f["name"] == predecessor)
        family["requires"].remove(source["milestones"][-1]["version"])
        reject(data)
    data = copy.deepcopy(register)
    data["reuse"]["SHA-512/t"] = "0.23.1"
    reject(data)
    data = copy.deepcopy(register)
    data["inventory"][0]["item"] = "unreviewed substitute"
    reject(data)
    data = copy.deepcopy(register)
    data["inventory"][0]["owners"] = ["SHA-2"]
    reject(data)
    data = copy.deepcopy(register)
    data["families"][0]["variants"].pop()
    reject(data)
    data = copy.deepcopy(register)
    data["families"][0]["api_contract"] = "unowned partial API"
    reject(data)
    data = copy.deepcopy(register)
    data["families"][0]["domain"] = "unknown"
    reject(data)
    data = copy.deepcopy(register)
    data["post_1_0_exception"] = "Other catalogue work may be deferred"
    reject(data)
    data = copy.deepcopy(register)
    data["reuse"]["SHA-2"] = "0.999.0"
    reject(data)
    data = copy.deepcopy(register)
    research = next(f for f in data["families"] if f["domain"] == "research")
    research["package"] = "brynja-hash-recommended"
    reject(data)
    data = copy.deepcopy(register)
    family = next(f for f in data["families"] if any(m["stage"]=="backend" for m in f["milestones"]))
    backend = next(m for m in family["milestones"] if m["stage"]=="backend")
    family["milestones"].remove(backend)
    family["milestones"].insert(1, backend)
    reject(data)
    print(f"catalogue migration covers 104 source rows and rejects {cases} scope/API/order regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
