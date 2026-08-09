#!/usr/bin/env python3
"""Check the repository's v0.11.0 unsafe exception."""

from pathlib import Path

import unsafe_policy


def main() -> int:
    unsafe_policy.validate(Path(__file__).resolve().parents[1])
    print("unsafe policy confines one documented volatile store to one private module")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
