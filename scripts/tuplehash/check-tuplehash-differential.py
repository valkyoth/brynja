#!/usr/bin/env python3
"""Compare TupleHash with an independently composed SP 800-185 oracle."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "assurance/tuplehash-differential/Cargo.toml"
CSHAKE_ORACLE = ROOT / "scripts/sha3/check-cshake-differential.py"
spec = importlib.util.spec_from_file_location("brynja_cshake_oracle", CSHAKE_ORACLE)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load independent cSHAKE oracle")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def right_encode(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big") + bytes([length])


def tuple_hash(
    rate: int,
    items: list[list[int]],
    custom: list[int],
    output_bits: int,
    xof: bool,
) -> bytes:
    encoded: list[int] = []
    for item in items:
        encoded.extend(oracle.encode_string(item))
    encoded.extend(oracle.byte_bits(right_encode(0 if xof else output_bits)))
    return oracle.cshake(
        rate,
        encoded,
        oracle.byte_bits(b"TupleHash"),
        custom,
        output_bits,
    )


def cases() -> list[tuple[str, bytes, int, list[tuple[bytes, int]], int, bytes]]:
    selected = []
    algorithms = (
        ("tuple128", 168, False),
        ("tuple256", 136, False),
        ("tuplexof128", 168, True),
        ("tuplexof256", 136, True),
    )
    lengths = (0, 1, 7, 8, 9, 63, 64, 65, 127, 168 * 8 - 1)
    for algorithm, rate, xof in algorithms:
        for index in range(64):
            custom_bits = (0, 3, 8, 17)[index % 4]
            custom = oracle.canonical(0x40_0000 + index, custom_bits)
            item_count = index % 5
            items = []
            item_bits = []
            for item_index in range(item_count):
                bits = lengths[(index + item_index) % len(lengths)]
                value = oracle.canonical(0x50_0000 + index * 17 + item_index, bits)
                items.append((value, bits))
                item_bits.append(oracle.byte_bits(value)[:bits])
            output_bits = (0, 1, 7, 8, 31, 32, 127, 128, 257, rate * 8 + 3)[index % 10]
            expected = tuple_hash(
                rate,
                item_bits,
                oracle.byte_bits(custom)[:custom_bits],
                output_bits,
                xof,
            )
            selected.append((algorithm, custom, custom_bits, items, output_bits, expected))
    return selected


def run_fixture(request: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="brynja-tuplehash-") as target:
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
    items = [oracle.byte_bits(bytes((0, 1, 2))), oracle.byte_bits(bytes((0x10, 0x11, 0x12, 0x13, 0x14, 0x15)))]
    fixed = tuple_hash(168, items, [], 256, False)
    if fixed.hex() != "c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1":
        raise RuntimeError("independent TupleHash oracle disagrees with official NIST sample")
    xof = tuple_hash(168, items, [], 256, True)
    if xof.hex() != "2f103cd7c32320353495c68de1a8129245c6325f6f2a3d608d92179c96e68488":
        raise RuntimeError("independent TupleHashXOF oracle disagrees with official NIST sample")


def main() -> int:
    verify_oracle()
    selected = cases()
    lines = []
    for algorithm, custom, custom_bits, items, output_bits, _ in selected:
        fields = [algorithm, str(custom_bits), custom.hex() or "-", str(output_bits), str(len(items))]
        for value, bits in items:
            fields.extend((str(bits), value.hex() or "-"))
        lines.append(" ".join(fields))
    result = run_fixture("\n".join(lines) + "\n")
    if result.returncode != 0:
        raise RuntimeError(f"TupleHash differential fixture failed:\n{result.stderr}")
    if result.stdout.splitlines() != [expected.hex() for *_, expected in selected]:
        raise RuntimeError("TupleHash arbitrary-bit differential mismatch")
    for invalid in (
        "tuple128 1 80 8 0\n",
        "tuplexof256 0 - 4096 0\n",
        "unknown 0 - 8 0\n",
        "tuple128 0 - 8 17\n",
        "tuple128 0 - 8 0 trailing\n",
    ):
        rejected = run_fixture(invalid)
        if rejected.returncode == 0 or rejected.stdout or "panicked" in rejected.stderr:
            raise RuntimeError("TupleHash differential fixture accepted malformed input")
    print(f"TupleHash/TupleHashXOF differential oracle: PASS ({len(selected)} arbitrary-bit results)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
