#!/usr/bin/env python3
"""Check the v0.12.0 emitted-code coverage contract."""

from pathlib import Path

import constant_time_evidence


def main() -> int:
    constant_time_evidence.validate(Path(__file__).resolve().parents[2])
    print(f"constant-time evidence binds {len(constant_time_evidence.COMPILERS)} compilers, "
          f"{len(constant_time_evidence.TARGETS)} targets, and 3 artifact levels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
