#!/usr/bin/env python3
"""Check the v0.24.4 SHA-2 and Keccak CPU acceleration boundary."""

from pathlib import Path

import cpu_boundary_policy


if __name__ == "__main__":
    cpu_boundary_policy.validate(Path("."))
    print("Original CPU candidate dispatch: seven kernels, zero admissions; opt-in raw static authority is checked separately")
