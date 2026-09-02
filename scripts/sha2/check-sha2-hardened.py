#!/usr/bin/env python3
"""Run v0.24.8 hardened SHA-2 source and behavioral acceptance."""

from pathlib import Path

import sha2_hardened


def main() -> int:
    sha2_hardened.validate(Path(__file__).resolve().parents[2])
    print(sha2_hardened.run_acceptance(), end="")
    print("complete hardened six-identity SHA-2 API: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
