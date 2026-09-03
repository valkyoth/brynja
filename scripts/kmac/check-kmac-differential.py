#!/usr/bin/env python3
"""Compare KMAC/KMACXOF with an independently composed SP 800-185 oracle."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "assurance/kmac-differential/Cargo.toml"
CSHAKE_ORACLE = ROOT / "scripts/sha3/check-cshake-differential.py"
spec = importlib.util.spec_from_file_location("brynja_cshake_oracle", CSHAKE_ORACLE)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load independent cSHAKE oracle")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def right_encode(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big") + bytes([length])


def kmac(rate: int, key: list[int], message: list[int], custom: list[int], output_bits: int, xof: bool) -> bytes:
    encoded_key = oracle.bytepad(oracle.encode_string(key), rate)
    encoded_length = oracle.byte_bits(right_encode(0 if xof else output_bits))
    return oracle.cshake(
        rate,
        encoded_key + message + encoded_length,
        oracle.byte_bits(b"KMAC"),
        custom,
        output_bits,
    )


def cases() -> list[tuple[str, bytes, int, bytes, int, bytes, int, int, bytes]]:
    selected = []
    algorithms = (
        ("kmac128", 168, False),
        ("kmac256", 136, False),
        ("kmacxof128", 168, True),
        ("kmacxof256", 136, True),
    )
    for algorithm, rate, xof in algorithms:
        boundaries = (0, 1, 7, 8, 9, rate * 8 - 1, rate * 8, rate * 8 + 1)
        for index in range(64):
            key_bits = (0, 7, 8, 127, 128, 255, 256)[index % 7]
            custom_bits = (0, 3, 8, 17)[index % 4]
            message_bits = boundaries[index % len(boundaries)]
            output_bits = (0, 1, 7, 8, 31, 32, 127, 128, 257, rate * 8 + 3)[index % 10]
            key = oracle.canonical(0x10_0000 + index, key_bits)
            custom = oracle.canonical(0x20_0000 + index, custom_bits)
            message = oracle.canonical(0x30_0000 + index, message_bits)
            expected = kmac(
                rate,
                oracle.byte_bits(key)[:key_bits],
                oracle.byte_bits(message)[:message_bits],
                oracle.byte_bits(custom)[:custom_bits],
                output_bits,
                xof,
            )
            selected.append((algorithm, key, key_bits, custom, custom_bits, message, message_bits, output_bits, expected))
    return selected


def run_fixture(request: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="brynja-kmac-") as target:
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


def verify_oracle() -> None:
    key = bytes(range(0x40, 0x60))
    actual = kmac(168, oracle.byte_bits(key), oracle.byte_bits(bytes(range(4))), [], 256, False)
    expected = "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e"
    if actual.hex() != expected:
        raise RuntimeError("independent KMAC oracle disagrees with official NIST sample")
    xof = kmac(136, oracle.byte_bits(key), oracle.byte_bits(bytes(range(4))), oracle.byte_bits(b"My Tagged Application"), 512, True)
    expected_xof = "1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa96faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b"
    if xof.hex() != expected_xof:
        raise RuntimeError("independent KMACXOF oracle disagrees with official NIST sample")


def main() -> int:
    verify_oracle()
    selected = cases()
    request = "\n".join(
        f"{algorithm} {key_bits} {key.hex() or '-'} {custom_bits} {custom.hex() or '-'} "
        f"{message_bits} {message.hex() or '-'} {output_bits}"
        for algorithm, key, key_bits, custom, custom_bits, message, message_bits, output_bits, _ in selected
    ) + "\n"
    result = run_fixture(request)
    if result.returncode != 0:
        raise RuntimeError(f"KMAC differential fixture failed:\n{result.stderr}")
    if result.stdout.splitlines() != [expected.hex() for *_, expected in selected]:
        raise RuntimeError("KMAC arbitrary-bit differential mismatch")
    for invalid in (
        "kmac128 1 80 0 - 0 - 8\n",
        "kmacxof256 0 - 0 - 0 - 4096\n",
        "unknown 0 - 0 - 0 - 8\n",
        "kmac128 0 - 0 - 0 - 8 trailing\n",
    ):
        rejected = run_fixture(invalid)
        if rejected.returncode == 0 or rejected.stdout or "panicked" in rejected.stderr:
            raise RuntimeError("KMAC differential fixture accepted malformed input")
    print(f"KMAC/KMACXOF differential oracle: PASS ({len(selected)} arbitrary-bit results)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
