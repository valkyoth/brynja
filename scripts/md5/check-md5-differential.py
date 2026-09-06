#!/usr/bin/env python3
"""Independent bit-string MD5 oracle; stdlib crypto is assurance-only."""
import hashlib
import math
import random
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = 'assurance/md5-public-api/Cargo.toml'
MASK = (1 << 32) - 1


def oracle(message, length):
    bits = ''.join(f'{byte:08b}' for byte in message)[:length] + '1'
    bits += '0' * ((448 - len(bits)) % 512)
    padded = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    padded += (length % (1 << 64)).to_bytes(8, 'little')
    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    shifts = ((7, 12, 17, 22), (5, 9, 14, 20), (4, 11, 16, 23), (6, 10, 15, 21))
    for offset in range(0, len(padded), 64):
        words = [int.from_bytes(padded[offset+i:offset+i+4], 'little') for i in range(0, 64, 4)]
        working = state.copy()
        for step in range(64):
            # Independently rotate which register is updated, as in RFC notation.
            index = (-step) % 4
            a, b, c, d = (working[(index+i) % 4] for i in range(4))
            phase = step // 16
            if phase == 0: f, word = d ^ (b & (c ^ d)), step
            elif phase == 1: f, word = c ^ (d & (b ^ c)), (5*step + 1) % 16
            elif phase == 2: f, word = b ^ c ^ d, (3*step + 5) % 16
            else: f, word = c ^ (b | ~d), (7*step) % 16
            value = (a + f + words[word] + int(abs(math.sin(step+1)) * (1 << 32))) & MASK
            shift = shifts[phase][step % 4]
            working[index] = (b + ((value << shift) | (value >> (32-shift)))) & MASK
        state = [(a+b) & MASK for a,b in zip(state, working)]
    return b''.join(word.to_bytes(4, 'little') for word in state).hex()


def main():
    subprocess.run(['cargo', 'build', '--locked', '--release', '--manifest-path', MANIFEST], cwd=ROOT, check=True)
    binary = ROOT / 'assurance/md5-public-api/target/release/brynja-md5-public-api-fixture'
    if not binary.is_file(): binary = binary.with_suffix('.exe')
    rng = random.Random(1321)
    lengths = sorted(set(range(1040)) | {rng.randrange(65537) for _ in range(96)})
    requests, expected = [], []
    for length in lengths:
        data = bytearray(rng.randbytes((length+7)//8))
        if length % 8: data[-1] &= (0xff << (8-length%8)) & 0xff
        digest = oracle(data, length)
        if length % 8 == 0: assert digest == hashlib.md5(data, usedforsecurity=False).hexdigest()
        requests.append(f'{length} {data.hex() or "-"}\n')
        expected.append(digest)
    result = subprocess.run([binary], input=''.join(requests), text=True, capture_output=True, timeout=180, check=True)
    assert result.stdout.splitlines() == expected, 'MD5 differential mismatch'
    for malformed in ('65537 -\n', '18446744073709551615 -\n', '999999999999999999999999 -\n',
                      '1 01\n', '8 -\n', '0 00\n', '8 0g\n', '8 0\n', '8 00 extra\n', 'x'*16416):
        result = subprocess.run([binary], input=malformed, text=True, capture_output=True, timeout=15)
        assert result.returncode != 0 and 'panicked' not in result.stderr
    print(f'MD5 independent bit differential: {len(expected)} cases; 10 malformed requests rejected')


if __name__ == '__main__': main()
