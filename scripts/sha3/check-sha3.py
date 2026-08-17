#!/usr/bin/env python3
"""Check the reviewed portable FIPS 202 fixed-output SHA-3 boundary."""

from pathlib import Path

import sha3_policy


def main() -> int:
    sha3_policy.validate(Path(__file__).resolve().parents[2])
    print("complete portable four-algorithm SHA-3 source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
