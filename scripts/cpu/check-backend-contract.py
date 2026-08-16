#!/usr/bin/env python3
"""Check the reviewed v0.13.1 CPU-backend contract."""

from pathlib import Path

import backend_contract_policy


if __name__ == "__main__":
    backend_contract_policy.validate(Path("."))
    print("CPU backend capability and dispatch source policy: PASS")
