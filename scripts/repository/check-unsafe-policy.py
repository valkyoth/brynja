#!/usr/bin/env python3
"""Check the repository's exact unsafe exception inventory."""

from pathlib import Path

import unsafe_policy


def main() -> int:
    unsafe_policy.validate(Path(__file__).resolve().parents[2])
    print(f"unsafe policy confines crypto/memory boundaries to {len(unsafe_policy.ALLOWED)} source-bound modules, including Windows enclave and Darwin resident OS adapters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
