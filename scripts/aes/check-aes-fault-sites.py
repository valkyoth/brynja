#!/usr/bin/env python3
"""Validate OPEN source-inventory bookkeeping, never fault qualification.

This optional development tool does not run experiments or change admission.
An anchor identifies a candidate source region, not a reviewed emitted site.
"""
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = "assurance/aes-fault-sites.json"
CLASSES = {"D1", "D2", "D3", "D4", "S1", "L1", "C1"}


def require(condition):
    if not condition:
        raise ValueError("invalid open candidate inventory")


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def nonempty(value):
    require(type(value) is str and bool(value.strip()))


def strings(value):
    require(type(value) is list and bool(value))
    for item in value:
        nonempty(item)
    require(len(value) == len(set(value)))


def file_at(root, name):
    nonempty(name)
    path = PurePosixPath(name)
    require(not path.is_absolute() and "\\" not in name)
    require(str(path) == name and all(p not in (".", "..") for p in path.parts))
    require(bool(path.parts))
    selected = root
    for part in path.parts:
        selected = selected / part
        require(not selected.is_symlink())
    require(selected.is_file())
    return selected


def no_duplicates(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result)
        result[name] = value
    return result


def load(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)


def byte_case_count(case):
    positions = sum(case["width_bytes"]) if case["position_bound"] == "width" else (
        len(case["width_bytes"]) * case["position_bound"])
    mutations = sum(m["last"] - m["first"] + 1 for m in case["mutations"])
    return positions * mutations * len(case["replicas"]) * len(case["owners"]) * len(case["paths"])


def byte_case_ids(case):
    """Deterministic public case labels only; never reads or mutates crypto data.

    Call validate() before enumeration. Identity includes the mutation family:
    two operations producing the same byte are distinct observations.
    """
    for width in case["width_bytes"]:
        bound = width if case["position_bound"] == "width" else case["position_bound"]
        for owner in case["owners"]:
            for path in case["paths"]:
                for replica in case["replicas"]:
                    for position in range(bound):
                        for mutation in case["mutations"]:
                            for value in range(mutation["first"], mutation["last"] + 1):
                                yield (f'{case["id"]}/aes{width * 8}/{owner}/{path}/{replica}/'
                                       f'byte{position}/{mutation["op"]}-{value}')


def validate_byte_cases(cases, site_ids, root):
    require(type(cases) is list and bool(cases))
    ids = set()
    for case in cases:
        fields(case, "id sites status width_bytes position_bound replicas owners paths fixture_byte mutations rust_test expected_trials")
        nonempty(case["id"])
        require(re.fullmatch(r"[a-z][a-z0-9-]*", case["id"]) is not None and case["id"] not in ids)
        ids.add(case["id"])
        strings(case["sites"])
        require(set(case["sites"]) <= site_ids)
        require(case["status"] == "source-only-emitted-open")
        require(case["width_bytes"] == [16, 24, 32])
        require(case["position_bound"] == "width" or (
            type(case["position_bound"]) is int and case["position_bound"] == 16))
        require(case["replicas"] == ["first", "second"])
        for name in ("owners", "paths"):
            strings(case[name])
            require(all(re.fullmatch(r"[a-z][a-z-]*", v) for v in case[name]))
        require(set(case["owners"]) <= {"cached", "operation-local", "capture-helper", "shared-import"})
        require(set(case["paths"]) <= {"encrypt-public", "encrypt-secret", "decrypt-secret", "copy", "import"})
        require(type(case["fixture_byte"]) is int and 0 <= case["fixture_byte"] <= 255)
        require(type(case["mutations"]) is list and bool(case["mutations"]))
        operations = set()
        for mutation in case["mutations"]:
            fields(mutation, "op first last")
            nonempty(mutation["op"])
            require(mutation["op"] in {"xor", "replace", "and", "or"} - operations)
            operations.add(mutation["op"])
            require(type(mutation["first"]) is int and type(mutation["last"]) is int)
            require(0 <= mutation["first"] <= mutation["last"] <= 255)
            require(mutation["op"] != "xor" or mutation["first"] > 0)
        fields(case["rust_test"], "path anchor")
        nonempty(case["rust_test"]["anchor"])
        test = file_at(root, case["rust_test"]["path"]).read_text(encoding="utf-8")
        require(test.count(case["rust_test"]["anchor"]) == 1)
        require(type(case["expected_trials"]) is int and case["expected_trials"] == byte_case_count(case))


def validate(data, root=ROOT):
    fields(data, "schema status qualification artifact_mappings scope mutation_families outcomes sites byte_case_sets dc1 negative_controls limitations")
    require(type(data["schema"]) is int and data["schema"] == 1)
    require(data["status"] == "open-source-candidate" and data["qualification"] == "none")
    # A future artifact/qualification format needs its own reviewed validator.
    # This source inventory deliberately cannot bless an executable.
    require(data["artifact_mappings"] == [])
    require(data["scope"] == {
        "widths": [128, 192, 256],
        "paths": ["encrypt-secret", "decrypt-secret", "encrypt-public"],
        "owners": ["cached", "operation-local"],
    })
    for name in ("mutation_families", "outcomes"):
        require(type(data[name]) is dict and bool(data[name]))
        for key, value in data[name].items():
            nonempty(key)
            nonempty(value)
    for name in ("negative_controls", "limitations"):
        strings(data[name])
    require(type(data["sites"]) is list and bool(data["sites"]))
    ids, classes, bypasses = set(), set(), set()
    for site in data["sites"]:
        fields(site, "id owners classes object phase source mutation outcome status evidence_runners remaining")
        strings(site["owners"])
        require(set(site["owners"]) <= set(data["scope"]["owners"]))
        nonempty(site["id"])
        require(re.fullmatch(r"[a-z][a-z0-9-]*", site["id"]) is not None)
        require(site["id"] not in ids)
        ids.add(site["id"])
        strings(site["classes"])
        require(set(site["classes"]) <= CLASSES)
        classes.update(site["classes"])
        if "C1" in site["classes"]:
            bypasses.add(site["id"])
        for name in ("object", "remaining", "mutation", "outcome"):
            nonempty(site[name])
        require(site["phase"] in {"import", "use", "import-and-use", "lifetime", "release"})
        require(site["mutation"] in data["mutation_families"])
        require(site["outcome"] in data["outcomes"])
        require(site["status"] == "open")
        fields(site["source"], "path anchor")
        nonempty(site["source"]["anchor"])
        source = file_at(root, site["source"]["path"]).read_text(encoding="utf-8")
        require(source.count(site["source"]["anchor"]) == 1)
        strings(site["evidence_runners"])
        for runner in site["evidence_runners"]:
            file_at(root, runner)
    require(classes == CLASSES)
    validate_byte_cases(data["byte_case_sets"], ids, root)
    fields(data["dc1"], "status data_classes bypass_sites rule")
    dc1 = data["dc1"]
    require(dc1["status"] == "open")
    strings(dc1["data_classes"])
    require(set(dc1["data_classes"]) == {"D1", "D2", "D3", "D4", "S1"})
    strings(dc1["bypass_sites"])
    require(set(dc1["bypass_sites"]) == bypasses)
    nonempty(dc1["rule"])
    return len(ids), len(bypasses)


def main():
    try:
        require(len(sys.argv) == 1)
        data = load(file_at(ROOT, INVENTORY))
        count, bypasses = validate(data)
    except (OSError, ValueError, TypeError, KeyError):
        print("Fault-site inventory bookkeeping invalid; no qualification performed.", file=sys.stderr)
        return 2
    print(f"Source bookkeeping valid: {count} OPEN candidate families; {bypasses} OPEN bypass families.")
    print(f'Source case definitions: {sum(byte_case_count(c) for c in data["byte_case_sets"])} trials; not execution receipts.')
    print("DC1 pairings and whole-artifact emitted-site mappings OPEN; qualified configurations: 0. No experiments executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
