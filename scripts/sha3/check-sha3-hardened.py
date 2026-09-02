#!/usr/bin/env python3
"""Run v0.24.10 hardened FIPS 202 source and behavioral acceptance."""

from pathlib import Path

import sha3_hardened


def main() -> int:
    sha3_hardened.validate(Path(__file__).resolve().parents[2])
    print(sha3_hardened.run_acceptance(), end="")
    print("complete hardened six-identity FIPS 202 API: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
