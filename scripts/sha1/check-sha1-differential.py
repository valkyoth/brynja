#!/usr/bin/env python3
"""Independent SHA-1 bit oracle and bounded malformed-corpus rejection."""
import hashlib
import random
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "assurance/sha1-public-api/Cargo.toml"
MASK = (1 << 32) - 1


def rol(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & MASK


def oracle(message, length):
    bits = ''.join(f'{byte:08b}' for byte in message)[:length] + '1'
    bits += '0' * ((448 - len(bits)) % 512) + f'{length:064b}'
    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    for offset in range(0, len(bits), 512):
        words = [int(bits[offset + i:offset + i + 32], 2) for i in range(0, 512, 32)]
        for i in range(16, 80):
            words.append(rol(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1))
        a, b, c, d, e = state
        for i, word in enumerate(words):
            if i < 20:
                function, constant = d ^ (b & (c ^ d)), 0x5a827999
            elif i < 40:
                function, constant = b ^ c ^ d, 0x6ed9eba1
            elif i < 60:
                function, constant = (b & c) | (d & (b | c)), 0x8f1bbcdc
            else:
                function, constant = b ^ c ^ d, 0xca62c1d6
            a, b, c, d, e = (rol(a, 5) + function + e + constant + word) & MASK, a, rol(b, 30), c, d
        state = [(left + right) & MASK for left, right in zip(state, (a, b, c, d, e))]
    return ''.join(f'{word:08x}' for word in state)


def main():
    subprocess.run(['cargo', 'build', '--locked', '--release', '--manifest-path', MANIFEST], cwd=ROOT, check=True)
    binary = ROOT / 'assurance/sha1-public-api/target/release/brynja-sha1-public-api-fixture'
    if not binary.is_file():
        binary = binary.with_suffix('.exe')
    rng = random.Random(0x1804)
    lengths = sorted(set(range(0, 1040)) | {rng.randrange(65537) for _ in range(96)})
    requests, expected = [], []
    for length in lengths:
        data = bytearray(rng.randbytes((length + 7) // 8))
        if length % 8: data[-1] &= (0xff << (8 - length % 8)) & 0xff
        digest = oracle(data, length)
        if length % 8 == 0:
            assert digest == hashlib.sha1(data, usedforsecurity=False).hexdigest()
        requests.append(f'{length} {data.hex() or "-"}\n')
        expected.append(digest)
    result = subprocess.run([binary], input=''.join(requests), text=True, capture_output=True, timeout=180, check=True)
    assert result.stdout.splitlines() == expected, 'SHA-1 differential mismatch'
    for malformed in ('65537 -\n', '18446744073709551615 -\n', '999999999999999999999999 -\n',
                      '1 01\n', '8 -\n', '0 00\n', '8 0g\n', '8 0\n', '8 00 extra\n', 'x' * 16416):
        result = subprocess.run([binary], input=malformed, text=True, capture_output=True, timeout=15)
        assert result.returncode != 0 and 'panicked' not in result.stderr
    print(f'SHA-1 independent bit differential: {len(expected)} cases; 10 malformed requests rejected')


if __name__ == '__main__':
    main()
