#!/usr/bin/env python3
"""Check or regenerate the deterministic v0.13.3 CPU evidence ledger."""

from __future__ import annotations

import argparse

import cpu_evidence_policy as evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    policy, admissions = evidence.load_and_validate()
    evidence.validate_all_records(policy, admissions)
    expected = evidence.json_bytes(evidence.build_ledger(policy, admissions))
    if args.write:
        if evidence.LEDGER.is_symlink():
            evidence.fail("CPU evidence ledger cannot be a symlink")
        evidence.LEDGER.write_bytes(expected)
    elif not evidence.LEDGER.is_file() or evidence.LEDGER.is_symlink():
        evidence.fail("missing regular CPU evidence ledger")
    elif evidence.LEDGER.read_bytes() != expected:
        evidence.fail("CPU evidence ledger is stale")
    print(
        f"CPU evidence registers {len(policy['lanes'])} lanes, "
        f"{len(policy['harnesses'])} harnesses, and zero admitted backends"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
