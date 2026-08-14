#!/usr/bin/env python3
"""Check the v0.21.0 canonical ASN.1 value boundary."""

from pathlib import Path

import asn1_value_policy


def main() -> int:
    asn1_value_policy.validate(Path(__file__).resolve().parents[1])
    print("canonical ASN.1 value source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
