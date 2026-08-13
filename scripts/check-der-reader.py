#!/usr/bin/env python3
"""Check the v0.20.0 bounded DER-reader boundary."""

from pathlib import Path

import der_reader_policy


def main() -> int:
    der_reader_policy.validate(Path(__file__).resolve().parents[1])
    print("bounded DER-reader source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
