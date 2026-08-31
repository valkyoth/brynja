#!/usr/bin/env python3
"""Capture an untrusted landing-page pin candidate for human review."""

from __future__ import annotations

import argparse
from pathlib import Path

import lifecycle_model as model
import lifecycle_network as network


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    args = parser.parse_args()
    candidate = network.landing_candidate(model.read_policy())
    network.write_new_json(args.artifact, candidate)
    print(f"wrote untrusted candidate for {len(candidate['landings'])} official landing pages; review before commit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
