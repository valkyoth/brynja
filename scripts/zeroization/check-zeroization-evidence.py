#!/usr/bin/env python3
"""Check the v0.11.0 emitted-code matrix and CI binding."""

from pathlib import Path

import zeroization_evidence


def main() -> int:
    zeroization_evidence.validate(Path(__file__).resolve().parents[2])
    print("zeroization evidence binds 11 compilers, 9 targets, and 3 artifact levels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
