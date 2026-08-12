#!/usr/bin/env python3
"""Check the v0.14.0 entropy and secure-random source boundary."""

from pathlib import Path

import entropy_contract_policy


def main() -> int:
    entropy_contract_policy.validate(Path(__file__).resolve().parents[1])
    print("entropy and secure-random source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
