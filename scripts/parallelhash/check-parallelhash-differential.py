#!/usr/bin/env python3
"""Compare ParallelHash with an independently composed SP 800-185 oracle."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "assurance/parallelhash-differential/Cargo.toml"
CSHAKE_ORACLE = ROOT / "scripts/sha3/check-cshake-differential.py"
spec = importlib.util.spec_from_file_location("brynja_cshake_oracle", CSHAKE_ORACLE)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load independent cSHAKE oracle")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def left_encode(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return bytes([length]) + value.to_bytes(length, "big")


def right_encode(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big") + bytes([length])


def parallel_hash(rate: int, message: list[int], block: int, custom: list[int], output_bits: int, xof: bool) -> bytes:
    block_bits = block * 8
    leaves = [message[index:index + block_bits] for index in range(0, len(message), block_bits)]
    encoded = oracle.byte_bits(left_encode(block))
    leaf_bits = 256 if rate == 168 else 512
    for leaf in leaves:
        encoded.extend(oracle.byte_bits(oracle.cshake(rate, leaf, [], [], leaf_bits)))
    encoded.extend(oracle.byte_bits(right_encode(len(leaves))))
    encoded.extend(oracle.byte_bits(right_encode(0 if xof else output_bits)))
    return oracle.cshake(rate, encoded, oracle.byte_bits(b"ParallelHash"), custom, output_bits)


def cases() -> list[tuple[str, bytes, int, bytes, int, int, bytes]]:
    selected = []
    algorithms = (
        ("parallel128", 168, False), ("parallel256", 136, False),
        ("parallelxof128", 168, True), ("parallelxof256", 136, True),
    )
    lengths = (0, 1, 7, 8, 9, 63, 64, 65, 127, 191, 192, 257, 576)
    blocks = (1, 2, 7, 8, 12, 17)
    outputs = (0, 1, 7, 8, 31, 32, 127, 128, 257, 1089)
    for algorithm, rate, xof in algorithms:
        for index in range(64):
            custom_bits = (0, 3, 8, 17)[index % 4]
            custom = oracle.canonical(0x710000 + index, custom_bits)
            input_bits = lengths[index % len(lengths)]
            message = oracle.canonical(0x720000 + index * 19, input_bits)
            block = blocks[index % len(blocks)]
            output_bits = outputs[index % len(outputs)]
            expected = parallel_hash(
                rate, oracle.byte_bits(message)[:input_bits], block,
                oracle.byte_bits(custom)[:custom_bits], output_bits, xof,
            )
            selected.append((algorithm, custom, custom_bits, message, input_bits, block, output_bits, expected))
    return selected


def run_fixture(request: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="brynja-parallelhash-") as target:
        environment["CARGO_TARGET_DIR"] = target
        return subprocess.run(
            ["cargo", "run", "--locked", "--quiet", "--manifest-path", str(MANIFEST)],
            cwd=ROOT, env=environment, input=request, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=240,
        )


def main() -> int:
    selected = cases()
    lines = [
        f"{algorithm} {custom_bits} {custom.hex() or '-'} {input_bits} {message.hex() or '-'} {block} {output_bits}"
        for algorithm, custom, custom_bits, message, input_bits, block, output_bits, _ in selected
    ]
    result = run_fixture("\n".join(lines) + "\n")
    if result.returncode != 0:
        raise RuntimeError(f"ParallelHash differential fixture failed:\n{result.stderr}")
    if result.stdout.splitlines() != [expected.hex() for *_, expected in selected]:
        raise RuntimeError("ParallelHash arbitrary-bit differential mismatch")
    for invalid in (
        "parallel128 0 - 0 - 0 8\n", "unknown 0 - 0 - 1 8\n",
        "parallel128 0 - 0 - 1 4096\n", "parallel128 1 80 0 - 1 8\n",
    ):
        rejected = run_fixture(invalid)
        if rejected.returncode == 0 or rejected.stdout or "panicked" in rejected.stderr:
            raise RuntimeError("ParallelHash differential fixture accepted malformed input")
    print(f"ParallelHash/ParallelHashXOF differential oracle: PASS ({len(selected)} arbitrary-bit results)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
