#!/usr/bin/env python3
"""Validate one CPU-backend evidence directory without changing repository state."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

import cpu_evidence_policy as evidence
import cpu_evidence_schema as schema


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--as-of", help="exact UTC timestamp used for reproducible review")
    args = parser.parse_args()
    policy, admissions = evidence.load_and_validate()
    evaluated = datetime.now(timezone.utc)
    if args.as_of:
        evaluated = schema.parse_utc(args.as_of)
    record = schema.read_toml_bounded(
        args.manifest,
        policy["limits"]["maximum_manifest_bytes"],
    )
    decision = schema.validate_record(
        record,
        policy,
        admissions,
        args.manifest.parent,
        evaluated,
    )
    state = "eligible" if decision["admission_eligible"] else "unadmitted"
    print(f"{decision['backend']} on {decision['lane']}: {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
