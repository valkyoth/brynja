#!/usr/bin/env python3
"""Validate v0.24.17 execution acceptance without granting native admission."""

import argparse
import execution_acceptance as acceptance


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        acceptance.write_hashes()
    acceptance.validate()
    print(acceptance.run_fixture(), end="")
    print("SP 800-185 execution policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
