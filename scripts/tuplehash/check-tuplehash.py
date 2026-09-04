#!/usr/bin/env python3
"""Check the reviewed TupleHash and TupleHashXOF boundary."""

from pathlib import Path

import tuplehash_policy


def main() -> int:
    tuplehash_policy.validate(Path(__file__).resolve().parents[2])
    print("complete TupleHash128/256 and TupleHashXOF128/256 source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
