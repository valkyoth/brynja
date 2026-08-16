#!/usr/bin/env python3
"""Run complete v0.23.4 SHA-2 public API and package acceptance."""

from __future__ import annotations

import tempfile
from pathlib import Path

import sha2_public_api as acceptance


def main() -> int:
    acceptance.validate_repository()
    print(acceptance.execute_acceptance(), end="")
    with tempfile.TemporaryDirectory(prefix="brynja-sha2-packages-") as temporary:
        destination = Path(temporary)
        roots = acceptance.package_roots(destination)
        consumer = acceptance.packaged_consumer(destination, roots)
        result = acceptance.run(
            ["cargo", "run", "--quiet", "--offline", "--manifest-path", str(consumer / "Cargo.toml")],
            cwd=consumer,
        )
        print(result.stdout, end="")
    print("Complete SHA-2 package-content acceptance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
