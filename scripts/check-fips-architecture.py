#!/usr/bin/env python3
"""Check the v0.17.0 FIPS-aware source boundary."""

from pathlib import Path

import fips_architecture_policy


def main() -> int:
    fips_architecture_policy.validate(Path(__file__).resolve().parents[1])
    print("FIPS-aware provider architecture source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
