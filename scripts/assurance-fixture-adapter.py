#!/usr/bin/env python3
"""Test-only adapter for the first-party assurance harness."""

from __future__ import annotations

import argparse
import json
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=("echo", "echo-alt", "reject", "diverge", "fail", "hang", "flood"),
    )
    args = parser.parse_args()
    payload = sys.stdin.buffer.read()
    if args.mode == "fail":
        return 1
    if args.mode == "hang":
        time.sleep(2)
    if args.mode == "flood":
        sys.stdout.write("x" * 4096)
        return 0
    output = payload.hex()
    result_class = "accept"
    if args.mode == "reject":
        result_class = "reject"
        output = ""
    elif args.mode == "diverge":
        output += "00"
    sys.stdout.write(
        json.dumps(
            {"class": result_class, "output": output},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
