#!/usr/bin/env python3
"""Check the repository's exact unsafe exception inventory."""

from pathlib import Path

import unsafe_policy


def main() -> int:
    unsafe_policy.validate(Path(__file__).resolve().parents[2])
    print("unsafe policy confines crypto/memory boundaries to 82 source-bound modules, including two development OS-memory adapters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
