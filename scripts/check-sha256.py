#!/usr/bin/env python3
"""Check the portable SHA-2 boundary through SHA-384 and SHA-512."""

from pathlib import Path

import sha256_policy


def main() -> int:
    sha256_policy.validate(Path(__file__).resolve().parents[1])
    print("portable SHA-224/SHA-256/SHA-384/SHA-512 source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
