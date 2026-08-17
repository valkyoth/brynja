#!/usr/bin/env python3
"""Compare Brynja SHA3-224/SHA3-256 with Python's independent OpenSSL/hashlib path."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "assurance/sha3-differential/Cargo.toml"


def message(length: int) -> bytes:
    state = 0x6A09E667
    output = bytearray()
    for _ in range(length):
        state = (state * 1_664_525 + 1_013_904_223) & 0xFFFF_FFFF
        output.append(state & 0xFF)
    return bytes(output)


def corpus() -> list[bytes]:
    lengths = set(range(0, 321))
    lengths.update((511, 512, 513, 1023, 1024, 1025, 4096))
    return [message(length) for length in sorted(lengths)]


def main() -> int:
    messages = corpus()
    requests: list[str] = []
    expected: list[str] = []
    for data in messages:
        encoded = data.hex() or "-"
        requests.extend((f"sha3-224 {encoded}", f"sha3-256 {encoded}"))
        expected.extend((hashlib.sha3_224(data).hexdigest(), hashlib.sha3_256(data).hexdigest()))

    with tempfile.TemporaryDirectory(prefix="brynja-sha3-target-") as target:
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = target
        environment["CARGO_INCREMENTAL"] = "0"
        result = subprocess.run(
            [
                "cargo",
                "run",
                "--locked",
                "--quiet",
                "--manifest-path",
                str(MANIFEST),
            ],
            cwd=ROOT,
            env=environment,
            input="\n".join(requests) + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(f"SHA-3 differential fixture failed:\n{result.stderr}")
    actual = result.stdout.splitlines()
    if actual != expected:
        for index, (wanted, observed) in enumerate(zip(expected, actual, strict=False)):
            if wanted != observed:
                raise RuntimeError(f"SHA-3 differential mismatch at result {index}")
        raise RuntimeError("SHA-3 differential result count mismatch")
    print(f"SHA3-224 and SHA3-256 match hashlib across {len(messages)} messages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
