#!/usr/bin/env python3
"""Check or refresh v0.24.11 combined modern-hash acceptance."""

from __future__ import annotations

import argparse
from pathlib import Path

import final_acceptance


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    if args.write:
        final_acceptance.write_hashes(root)
    final_acceptance.validate(root)
    print(final_acceptance.run_fixture(root), end="")
    print("Combined SHA-2 and SHA-3/SHAKE closure policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
