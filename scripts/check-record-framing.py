#!/usr/bin/env python3
"""Check the v0.19.0 TLS and DTLS record-framing boundary."""

from pathlib import Path

import record_framing_policy


def main() -> int:
    record_framing_policy.validate(Path(__file__).resolve().parents[1])
    print("TLS and DTLS record-framing source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
