#!/usr/bin/env python3
"""Compare cSHAKE with an independently coded Keccak/SP 800-185 oracle."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "assurance/cshake-differential/Cargo.toml"
ORACLE_PATH = ROOT / "scripts/sha3/check-sha3-bit-differential.py"
spec = importlib.util.spec_from_file_location("brynja_keccak_oracle", ORACLE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load independent Keccak oracle")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def byte_bits(data: bytes) -> list[int]:
    return [(byte >> position) & 1 for byte in data for position in range(8)]


def bits_bytes(bits: list[int]) -> bytes:
    output = bytearray((len(bits) + 7) // 8)
    for position, value in enumerate(bits):
        output[position // 8] |= value << (position % 8)
    return bytes(output)


def left_encode(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return bytes([length]) + value.to_bytes(length, "big")


def encode_string(bits: list[int]) -> list[int]:
    return byte_bits(left_encode(len(bits))) + bits


def bytepad(bits: list[int], width: int) -> list[int]:
    output = byte_bits(left_encode(width)) + bits
    output.extend([0] * ((-len(output)) % 8))
    output.extend([0] * ((-(len(output) // 8)) % width * 8))
    return output


def sponge(rate: int, message: list[int], output_bits: int, customized: bool) -> bytes:
    suffix = [0, 0, 1] if customized else [1, 1, 1, 1, 1]
    rate_bits = rate * 8
    padded = message + suffix
    padded.extend([0] * ((rate_bits - 1 - len(padded)) % rate_bits))
    padded.append(1)
    state = [0] * 25
    for start in range(0, len(padded), rate_bits):
        for position, value in enumerate(padded[start:start + rate_bits]):
            state[position // 64] ^= value << (position % 64)
        oracle.permute(state)
    output = [0] * output_bits
    for position in range(output_bits):
        if position and position % rate_bits == 0:
            oracle.permute(state)
        relative = position % rate_bits
        output[position] = (state[relative // 64] >> (relative % 64)) & 1
    return bits_bytes(output)


def cshake(rate: int, x: list[int], n: list[int], s: list[int], output_bits: int) -> bytes:
    customized = bool(n or s)
    prefix = bytepad(encode_string(n) + encode_string(s), rate) if customized else []
    return sponge(rate, prefix + x, output_bits, customized)


def canonical(seed: int, bit_length: int) -> bytes:
    output = bytearray((bit_length + 7) // 8)
    state = seed
    for index in range(len(output)):
        state = (state * 1_664_525 + 1_013_904_223) & 0xFFFF_FFFF
        output[index] = state & 0xFF
    if bit_length % 8:
        output[-1] &= (1 << (bit_length % 8)) - 1
    return bytes(output)


def cases() -> list[tuple[str, bytes, int, bytes, int, bytes, int, int, bytes]]:
    values = []
    for algorithm, rate in (("cshake128", 168), ("cshake256", 136)):
        for n_bits, s_bits in ((0, 0), (3, 0), (0, 5), (9, 11), (16, 24)):
            for x_bits in (0, 1, 7, 8, 9, rate * 8 - 1, rate * 8, rate * 8 + 3):
                for output_bits in (0, 1, 7, 8, 257, rate * 8 + 3):
                    n = canonical(0x11 ^ n_bits, n_bits)
                    s = canonical(0x22 ^ s_bits, s_bits)
                    x = canonical(0x33 ^ x_bits, x_bits)
                    expected = cshake(
                        rate,
                        byte_bits(x)[:x_bits],
                        byte_bits(n)[:n_bits],
                        byte_bits(s)[:s_bits],
                        output_bits,
                    )
                    values.append((algorithm, n, n_bits, s, s_bits, x, x_bits, output_bits, expected))
    return values


def run_fixture(request: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="brynja-cshake-") as target:
        environment["CARGO_TARGET_DIR"] = target
        return subprocess.run(
            ["cargo", "run", "--locked", "--quiet", "--manifest-path", str(MANIFEST)],
            cwd=ROOT,
            env=environment,
            input=request,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=240,
        )


def main() -> int:
    official = (
        (168, bytes(range(4)), 256, "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5"),
        (136, bytes(range(4)), 512, "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c"),
    )
    for rate, message, output_bits, expected in official:
        actual = cshake(
            rate,
            byte_bits(message),
            [],
            byte_bits(b"Email Signature"),
            output_bits,
        )
        if actual.hex() != expected:
            raise RuntimeError("independent cSHAKE oracle disagrees with official NIST sample")
    selected = cases()
    request = "\n".join(
        f"{algorithm} {n_bits} {n.hex() or '-'} {s_bits} {s.hex() or '-'} "
        f"{x_bits} {x.hex() or '-'} {output_bits}"
        for algorithm, n, n_bits, s, s_bits, x, x_bits, output_bits, _ in selected
    ) + "\n"
    result = run_fixture(request)
    if result.returncode != 0:
        raise RuntimeError(f"cSHAKE differential fixture failed:\n{result.stderr}")
    if result.stdout.splitlines() != [expected.hex() for *_, expected in selected]:
        raise RuntimeError("cSHAKE arbitrary-bit differential mismatch")
    for invalid in (
        "cshake128 1 80 0 - 0 - 8\n",
        "cshake256 0 - 0 - 0 - 4096\n",
        "unknown 0 - 0 - 0 - 8\n",
    ):
        rejected = run_fixture(invalid)
        if rejected.returncode == 0 or rejected.stdout or "panicked" in rejected.stderr:
            raise RuntimeError("cSHAKE differential fixture accepted malformed input")
    print(f"cSHAKE differential oracle: PASS ({len(selected)} arbitrary-bit results)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
