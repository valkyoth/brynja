#!/usr/bin/env python3
"""Check the v0.15.0 typed clock source boundary."""

from pathlib import Path

import clock_contract_policy


def main() -> int:
    clock_contract_policy.validate(Path(__file__).resolve().parents[2])
    print("typed wall and monotonic clock source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
