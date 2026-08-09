#!/usr/bin/env python3
"""Check the v0.12.0 constant-time source and evidence boundary."""

from pathlib import Path

import constant_time_policy


def main() -> int:
    constant_time_policy.validate(Path(__file__).resolve().parents[1])
    print("constant-time foundation source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
