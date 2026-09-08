"""Independent fixed-corpus IV oracle; no Rust constants or implementation reads."""
from __future__ import annotations

import argparse
import hashlib
from math import isqrt
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "crates/brynja-hash-sha2/tests/vectors/general-sha512-t-iv.txt"
MASK = (1 << 64) - 1


def cube_root(n: int) -> int:
    low, high = 0, 1 << ((n.bit_length() + 2) // 3)
    while low < high:
        middle = (low + high + 1) // 2
        if middle**3 <= n:
            low = middle
        else:
            high = middle - 1
    return low


def primes() -> list[int]:
    result = []
    for candidate in range(2, 410):
        if all(candidate % divisor for divisor in range(2, isqrt(candidate) + 1)):
            result.append(candidate)
    if len(result) != 80:
        raise ValueError("prime constant derivation failed")
    return result


PRIMES = primes()
INITIAL = [isqrt(p << 128) & MASK for p in PRIMES[:8]]
CONSTANTS = [cube_root(p << 192) & MASK for p in PRIMES]


def rotate(n: int, k: int) -> int:
    return (n >> k | n << (64 - k)) & MASK


def hash_bytes(message: bytes, initial: list[int]) -> list[int]:
    # Only fixed in-process corpora are supplied; this is not a streaming API.
    data = message + b"\x80"
    data += bytes((112 - len(data)) % 128) + (len(message) * 8).to_bytes(16, "big")
    state = initial.copy()
    for offset in range(0, len(data), 128):
        schedule = [int.from_bytes(data[i:i + 8], "big") for i in range(offset, offset + 128, 8)]
        for i in range(16, 80):
            x, y = schedule[i - 15], schedule[i - 2]
            s0 = rotate(x, 1) ^ rotate(x, 8) ^ (x >> 7)
            s1 = rotate(y, 19) ^ rotate(y, 61) ^ (y >> 6)
            schedule.append((schedule[i - 16] + s0 + schedule[i - 7] + s1) & MASK)
        work = state.copy()
        for i in range(80):
            a, b, c, d, e, f, g, h = work
            first = h + (rotate(e, 14) ^ rotate(e, 18) ^ rotate(e, 41))
            first += (e & f) ^ ((~e) & g)
            first += CONSTANTS[i] + schedule[i]
            second = (rotate(a, 28) ^ rotate(a, 34) ^ rotate(a, 39)) + ((a & b) ^ (a & c) ^ (b & c))
            work = [(first + second) & MASK, a, b, c, (d + first) & MASK, e, f, g]
        state = [(left + right) & MASK for left, right in zip(state, work)]
    return state


def render() -> bytes:
    # Independently sanity-check derived constants, padding and compression.
    for message in (b"", b"abc", bytes(range(256))):
        actual = b"".join(word.to_bytes(8, "big") for word in hash_bytes(message, INITIAL))
        if actual != hashlib.sha512(message).digest():
            raise ValueError("independent SHA-512 self-check failed")
    rows = []
    for t in range(1, 512):
        if t == 384:
            continue
        label = f"SHA-512/{t}".encode("ascii")
        words = hash_bytes(label, [word ^ 0xa5a5a5a5a5a5a5a5 for word in INITIAL])
        rows.append(str(t) + "".join(f" {word:016x}" for word in words))
    return ("\n".join(rows) + "\n").encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.write:
        VECTORS.write_bytes(expected)
    with VECTORS.open("rb") as stream:
        actual = stream.read(100_001).replace(b"\r\n", b"\n")
    if actual != expected:
        raise ValueError("all-parameter IV vector corpus differs from independent oracle")
    print("Independent general SHA-512/t IV corpus: all 510 parameters PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
