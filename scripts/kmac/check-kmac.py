#!/usr/bin/env python3
"""Check the reviewed KMAC and KMACXOF boundary."""

from pathlib import Path

import kmac_policy


def main() -> int:
    kmac_policy.validate(Path(__file__).resolve().parents[2])
    print("complete KMAC128/KMAC256/KMACXOF128/KMACXOF256 source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
