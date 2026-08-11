#!/usr/bin/env python3
"""Check the v0.13.2 CPU acceleration package boundary."""

from pathlib import Path

import cpu_boundary_policy


if __name__ == "__main__":
    cpu_boundary_policy.validate(Path("."))
    print("CPU acceleration packages reserve eight backends and admit zero implementations")
