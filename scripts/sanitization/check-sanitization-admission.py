#!/usr/bin/env python3
"""Check the v0.11.1 sanitization admission evidence."""

from __future__ import annotations

import argparse
from pathlib import Path

import sanitization_admission


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--package", type=Path)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    sanitization_admission.validate(root, arguments.package, arguments.online)
    suffix = ", crates.io freshness and package bytes" if arguments.online else ""
    print(f"sanitization 2.0.3 admission record, isolation{suffix}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
