#!/usr/bin/env python3
"""Fail-closed check of OPEN source-stage expansion; never qualification."""
import importlib.util
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "fault_sites", Path(__file__).with_name("check-aes-fault-sites.py"))
SITES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SITES)
LEDGER = "assurance/aes-fault-stage-expansion.json"


def validate(ledger, inventory):
    SITES.fields(ledger, "schema status qualification source_inventory exact_emitted_sites dc1_temporal_pairings required_site_identity families bypass_stage_inventory limits")
    SITES.require(ledger["schema"] == 1)
    SITES.require(ledger["status"] == "source-stage-expansion-only")
    SITES.require(ledger["qualification"] == "none")
    SITES.require(ledger["source_inventory"] == SITES.INVENTORY)
    SITES.require(ledger["exact_emitted_sites"] == [])
    SITES.require(ledger["dc1_temporal_pairings"] == [])
    SITES.require(ledger["required_site_identity"] == [
        "artifact-sha256", "owner", "key-width", "direction", "source-family",
        "stage", "instruction-address", "fault-location", "mutation", "persistence"])
    SITES.strings(ledger["limits"])
    rows = ledger["families"]
    SITES.require(type(rows) is list)
    source_ids = {site["id"] for site in inventory["sites"]}
    SITES.require(len(rows) == len(source_ids))
    seen = set()
    stage_count = 0
    for row in rows:
        SITES.fields(row, "id stages")
        SITES.require(row["id"] in source_ids and row["id"] not in seen)
        seen.add(row["id"])
        SITES.strings(row["stages"])
        SITES.require(len(row["stages"]) >= 2)
        SITES.require(all(re.fullmatch(r"[a-z][a-z0-9-]*", stage)
                              for stage in row["stages"]))
        stage_count += len(row["stages"])
    SITES.require(seen == source_ids)
    bypass_ids = set(inventory["dc1"]["bypass_sites"])
    SITES.require(len(bypass_ids) == 9 and bypass_ids <= seen)
    bypass_rows = ledger["bypass_stage_inventory"]
    SITES.require(type(bypass_rows) is list and len(bypass_rows) == len(bypass_ids))
    stage_lookup = {row["id"]: set(row["stages"]) for row in rows}
    bypass_seen = set()
    bypass_stage_count = 0
    for row in bypass_rows:
        SITES.fields(row, "family stages status")
        family = row["family"]
        SITES.require(family in bypass_ids and family not in bypass_seen)
        bypass_seen.add(family)
        SITES.require(row["status"] == "emitted-decision-open")
        SITES.strings(row["stages"])
        SITES.require(set(row["stages"]) <= stage_lookup[family])
        bypass_stage_count += len(row["stages"])
    SITES.require(bypass_seen == bypass_ids)
    return len(seen), stage_count, len(bypass_ids), bypass_stage_count


def main():
    try:
        inventory = SITES.load(SITES.file_at(ROOT, SITES.INVENTORY))
        SITES.validate(inventory)
        ledger = SITES.load(SITES.file_at(ROOT, LEDGER))
        families, stages, bypasses, bypass_stages = validate(ledger, inventory)
    except (OSError, ValueError, TypeError, KeyError):
        print("Fault stage expansion invalid; no qualification performed.", file=sys.stderr)
        return 2
    print(f"Source-stage ledger: {stages} candidate stages across {families} OPEN families; {bypass_stages} decision stages in {bypasses} OPEN bypass families.")
    print("Exact instruction sites and DC1 temporal pairings: OPEN. Qualified configurations: 0.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
