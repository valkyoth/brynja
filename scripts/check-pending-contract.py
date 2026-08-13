#!/usr/bin/env python3
"""Check the v0.16.0 pending-operation source boundary."""

from pathlib import Path

import pending_contract_policy


def main() -> int:
    pending_contract_policy.validate(Path(__file__).resolve().parents[1])
    print("pending operation and accelerator lifecycle source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
