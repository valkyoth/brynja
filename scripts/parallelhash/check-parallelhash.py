#!/usr/bin/env python3
"""Check the reviewed ParallelHash boundary."""

from pathlib import Path

import parallelhash_policy


def main() -> int:
    parallelhash_policy.validate(Path(__file__).resolve().parents[2])
    print("complete ParallelHash128/256 and ParallelHashXOF128/256 source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
