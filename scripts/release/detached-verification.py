#!/usr/bin/env python3
"""Start, inspect, cancel and validate a frozen verification job."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import detached_catalog as catalog
import detached_job as jobs
import detached_manifest as records
import verification_plan as plans


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    start = sub.add_parser("start")
    start.add_argument("job", type=Path)
    start.add_argument("--phase", choices=catalog.PHASES, action="append", required=True)
    start.add_argument("--base")
    start.add_argument("--approve-full")
    start.add_argument("--seconds", type=int, default=14400)
    start.add_argument("--log-bytes", type=int, default=256 * 1024 * 1024)
    start.add_argument("--shards", type=int, default=1)
    start.add_argument("--workers", type=int, default=1)
    for name in ("status", "collect", "cancel", "_worker"):
        child = sub.add_parser(name)
        child.add_argument("job", type=Path)
        child.add_argument("--receipt", required=True)
    args = parser.parse_args()
    try:
        job = records.safe_path(args.job)
        if args.action == "start":
            receipt = jobs.start(plans.ROOT, job, args.phase, args.approve_full,
                                 args.base, args.seconds, args.log_bytes, args.shards, args.workers)
            print(json.dumps({"job": str(job), "receipt": receipt, "state": "started"}))
        elif args.action == "_worker":
            return jobs.worker(job, args.receipt)
        else:
            jobs.load(job, args.receipt)
            if args.action == "collect":
                print(json.dumps(jobs.collect(job, args.receipt, plans.ROOT), sort_keys=True))
            elif args.action == "cancel":
                if not (job / "cancel").exists():
                    with (job / "cancel").open("xb"):
                        pass
                print("Cancellation requested; collect will not accept this run.")
            else:
                print(json.dumps(records.read(job / "state.json"), sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Detached verification rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
