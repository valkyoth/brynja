#!/usr/bin/env python3
"""Check Brynja's first-party Rust cryptographic implementation rule."""

from pathlib import Path

import first_party_rust_crypto


def main() -> int:
    first_party_rust_crypto.validate(Path(__file__).resolve().parents[2])
    print("first-party Rust cryptography golden rule: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
