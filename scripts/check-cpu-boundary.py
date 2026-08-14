#!/usr/bin/env python3
"""Check the v0.22.2 SHA-256 CPU acceleration boundary."""

from pathlib import Path

import cpu_boundary_policy


if __name__ == "__main__":
    cpu_boundary_policy.validate(Path("."))
    print("CPU boundary implements three SHA-256 candidates and admits zero pending native evidence")
