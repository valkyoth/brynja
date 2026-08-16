#!/usr/bin/env python3
"""Check the v0.18.1 bounded observational security-event schema."""

from pathlib import Path

import security_event_policy


def main() -> int:
    security_event_policy.validate(Path(__file__).resolve().parents[2])
    print("bounded observational security-event source policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

