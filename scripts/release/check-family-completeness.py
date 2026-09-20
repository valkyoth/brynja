#!/usr/bin/env python3
"""Report family hardening/acceleration gaps without starting expensive checks."""

import argparse
import json
import subprocess
from pathlib import Path

import family_completeness as model


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="milestone, e.g. 0.25.0")
    parser.add_argument("--closing-version", required=True, help="family acceptance, e.g. 0.25.2")
    parser.add_argument("--review", type=Path, help="explicit reviewer-authored JSON")
    parser.add_argument("--template", action="store_true", help="print UNREVIEWED template; no files written")
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    args = parser.parse_args()
    if args.template and args.review:
        parser.error("--template and --review cannot be combined")
    root = Path(__file__).resolve().parents[2]
    try:
        plans = model.roadmap(root)
        expected = model.template(args.version, args.closing_version, model.implementation_snapshot(root), plans)
        if args.template:
            print(json.dumps(expected, indent=2))
            return 0
        record = json.loads(args.review.read_text(encoding="utf-8")) if args.review else expected
        result = model.audit(root, record, expected, plans)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print("Family development review invalid: " + str(error))
        return 1
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("Family development review: " + result["result"])
        for issue in result["issues"]:
            print("- " + issue)
        for version, title in result["available_follow_ups"].items():
            print(f"Existing follow-up: v{version} — {title}")
        print(result["limitations"])
    return 2 if result["issues"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
