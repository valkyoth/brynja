#!/usr/bin/env python3
"""Compare Brynja FIPS 202 bit APIs with an independent Keccak oracle."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "assurance/sha3-bit-differential/Cargo.toml"
VECTORS = ROOT / "crates/brynja-hash-sha3/tests/vectors/nist-bit-selected.txt"
MASK64 = (1 << 64) - 1
ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
ROTATIONS = (
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
    25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
)
RATES = {"sha3-224": 144, "sha3-256": 136, "sha3-384": 104,
         "sha3-512": 72, "shake128": 168, "shake256": 136}
OUTPUTS = {"sha3-224": 224, "sha3-256": 256, "sha3-384": 384, "sha3-512": 512}


def rotate(value: int, amount: int) -> int:
    if amount == 0:
        return value
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def permute(state: list[int]) -> None:
    for constant in ROUND_CONSTANTS:
        columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        for x in range(5):
            delta = columns[(x - 1) % 5] ^ rotate(columns[(x + 1) % 5], 1)
            for y in range(5):
                state[x + 5 * y] ^= delta
        rearranged = [0] * 25
        for x in range(5):
            for y in range(5):
                rearranged[y + 5 * ((2 * x + 3 * y) % 5)] = rotate(state[x + 5 * y], ROTATIONS[x + 5 * y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = rearranged[x + 5 * y] ^ ((~rearranged[(x + 1) % 5 + 5 * y]) & rearranged[(x + 2) % 5 + 5 * y])
        state[0] ^= constant


def bit_at(data: bytes, position: int) -> int:
    return (data[position // 8] >> (position % 8)) & 1


def keccak(algorithm: str, message: bytes, input_bits: int, output_bits: int) -> bytes:
    rate_bits = RATES[algorithm] * 8
    suffix = 0x06 if algorithm.startswith("sha3") else 0x1F
    suffix_bits = 3 if algorithm.startswith("sha3") else 5
    padded = [bit_at(message, position) for position in range(input_bits)]
    padded.extend((suffix >> position) & 1 for position in range(suffix_bits))
    while len(padded) % rate_bits != rate_bits - 1:
        padded.append(0)
    padded.append(1)
    state = [0] * 25
    for start in range(0, len(padded), rate_bits):
        for position, value in enumerate(padded[start:start + rate_bits]):
            state[position // 64] ^= value << (position % 64)
        permute(state)
    output = bytearray((output_bits + 7) // 8)
    for position in range(output_bits):
        if position != 0 and position % rate_bits == 0:
            permute(state)
        output[position // 8] |= ((state[(position % rate_bits) // 64] >> (position % 64)) & 1) << (position % 8)
    return bytes(output)


def selected_vectors() -> list[tuple[str, int, int, bytes, bytes]]:
    selected = []
    for raw in VECTORS.read_text(encoding="ascii").splitlines():
        if not raw or raw.startswith("#"):
            continue
        algorithm, input_bits, output_bits, message, output = raw.split()
        exact_input_bits = int(input_bits)
        decoded = bytes.fromhex(message)[:(exact_input_bits + 7) // 8]
        selected.append((algorithm, exact_input_bits, int(output_bits), decoded, bytes.fromhex(output)))
    return selected


def generated_cases() -> list[tuple[str, int, int, bytes, bytes]]:
    cases = []
    for algorithm, rate in RATES.items():
        lengths = {*range(16), rate * 8 - 7, rate * 8 - 1, rate * 8, rate * 8 + 1, rate * 8 + 7, rate * 16 + 3}
        for input_bits in sorted(lengths):
            message = bytearray((input_bits + 7) // 8)
            state = 0x6A09E667 ^ input_bits
            for index in range(len(message)):
                state = (state * 1_664_525 + 1_013_904_223) & 0xFFFF_FFFF
                message[index] = state & 0xFF
            if input_bits % 8:
                message[-1] &= (1 << (input_bits % 8)) - 1
            outputs = [OUTPUTS[algorithm]] if algorithm in OUTPUTS else [0, 1, 7, 8, 9, 100, 109, rate * 8 + 3]
            for output_bits in outputs:
                expected = keccak(algorithm, message, input_bits, output_bits)
                cases.append((algorithm, input_bits, output_bits, bytes(message), expected))
    return cases


def run_fixture(request: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="brynja-sha3-bit-") as target:
        environment["CARGO_TARGET_DIR"] = target
        return subprocess.run(
            ["cargo", "run", "--locked", "--quiet", "--manifest-path", str(MANIFEST)],
            cwd=ROOT, env=environment, input=request, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=240,
        )


def main() -> int:
    official = selected_vectors()
    for algorithm, input_bits, output_bits, message, expected in official:
        if keccak(algorithm, message, input_bits, output_bits) != expected:
            raise RuntimeError(f"independent oracle disagrees with NIST: {algorithm}/{input_bits}/{output_bits}")
    cases = official + generated_cases()
    request = "\n".join(
        f"{algorithm} {input_bits} {output_bits} {message.hex() or '-'}"
        for algorithm, input_bits, output_bits, message, _expected in cases
    ) + "\n"
    result = run_fixture(request)
    expected = [value.hex() for *_prefix, value in cases]
    if result.returncode != 0:
        raise RuntimeError(f"bit differential fixture failed:\n{result.stderr}")
    if result.stdout.splitlines() != expected:
        raise RuntimeError("FIPS 202 bit differential mismatch")
    invalid = (
        "shake128 1 1 80\n",
        "shake128 1 4096 01\n",
        "sha3-256 9 256 01\n",
        "unknown 0 0 -\n",
    )
    for request in invalid:
        rejected = run_fixture(request)
        if rejected.returncode == 0 or rejected.stdout or "panicked" in rejected.stderr:
            raise RuntimeError("bit differential fixture accepted malformed input")
    print(f"{len(official)} NIST and {len(cases) - len(official)} independent bit cases passed; malformed inputs reject cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
