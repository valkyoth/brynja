#!/usr/bin/env python3
"""Check the v0.24.4 SHA-2 and Keccak CPU acceleration boundary."""

from pathlib import Path

import cpu_boundary_policy


if __name__ == "__main__":
    cpu_boundary_policy.validate(Path("."))
    print("CPU boundary implements five SHA-2 and two Keccak candidates, records x86 SHA-512 and RISC-V Keccak scalar-only, and admits zero pending native evidence")
