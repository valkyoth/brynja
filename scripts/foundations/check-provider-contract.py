#!/usr/bin/env python3
"""Check the v0.13.0 provider capability and opaque-handle boundary."""

from pathlib import Path

import provider_contract_policy


def main() -> int:
    provider_contract_policy.validate(Path(__file__).resolve().parents[2])
    print("provider capability and opaque-handle source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
