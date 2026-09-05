#!/usr/bin/env python3
"""Capture a clean-commit, privacy-minimized native report for manual review."""

import argparse
from pathlib import Path

import native_capture


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lane", choices=tuple(native_capture.LANES))
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    native_capture.capture(args.lane, args.output)
    print("Native SP 800-185 report captured; operator review required. No backend admitted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
