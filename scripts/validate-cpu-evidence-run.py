#!/usr/bin/env python3
"""Validate one detached SHA-256 native candidate-run bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

import cpu_evidence_run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    arguments = parser.parse_args()
    manifest = cpu_evidence_run.validate_bundle(arguments.bundle)
    print(
        f"{manifest['backend']} on {manifest['lane']}: "
        "valid non-authorizing candidate observation"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
