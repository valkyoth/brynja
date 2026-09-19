#!/usr/bin/env python3
"""Check the repository's exact unsafe exception inventory."""

from pathlib import Path

import unsafe_policy


def main() -> int:
    unsafe_policy.validate(Path(__file__).resolve().parents[2])
    print("unsafe policy confines core/hash-interface secret-memory primitives and SHA-2/Keccak and isolated legacy SHA-1/MD5 low-level code to seventy-nine reviewed modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
