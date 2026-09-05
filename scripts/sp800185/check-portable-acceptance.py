#!/usr/bin/env python3
"""Check or refresh v0.24.16 portable SP 800-185 acceptance."""

from __future__ import annotations

import argparse

import portable_acceptance


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        portable_acceptance.write_hashes()
    portable_acceptance.validate()
    print(portable_acceptance.run_fixture(), end="")
    print("SP 800-185 portable closure policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
