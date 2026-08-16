#!/usr/bin/env python3
"""Check the complete portable FIPS 180-4 SHA-2 boundary."""

from pathlib import Path

import sha256_policy


def main() -> int:
    sha256_policy.validate(Path(__file__).resolve().parents[1])
    print("complete portable six-algorithm SHA-2 source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
