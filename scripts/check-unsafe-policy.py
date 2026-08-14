#!/usr/bin/env python3
"""Check the repository's exact unsafe exception inventory."""

from pathlib import Path

import unsafe_policy


def main() -> int:
    unsafe_policy.validate(Path(__file__).resolve().parents[1])
    print("unsafe policy confines volatile clearing and SHA-256 CPU low-level code to six reviewed modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
