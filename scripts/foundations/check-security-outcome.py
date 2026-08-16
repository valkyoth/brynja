#!/usr/bin/env python3
"""Check the v0.18.0 mandatory security-outcome contract."""

from pathlib import Path

import security_outcome_policy


def main() -> int:
    security_outcome_policy.validate(Path(__file__).resolve().parents[2])
    print("mandatory security-outcome authority source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
