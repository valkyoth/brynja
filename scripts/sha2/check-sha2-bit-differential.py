#!/usr/bin/env python3
"""Differentially test every SHA-2 bit API against an independent oracle."""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "assurance/sha2-bit-differential/Cargo.toml"
MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1

K32 = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

K64 = (
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC, 0x3956C25BF348B538, 0x59F111F1B605D019,
    0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242,
    0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
    0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
    0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC,
    0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6,
    0x92722C851482353B, 0xA2BFE8A14CF10364, 0xA81A664BBC423001,
    0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
    0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC,
    0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915,
    0xC67178F2E372532B, 0xCA273ECEEA26619C, 0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA,
    0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
)

CONFIG = {
    "sha224": ((0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
                0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4), 28),
    "sha256": ((0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19), 32),
    "sha384": ((0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17,
                0x152FECD8F70E5939, 0x67332667FFC00B31, 0x8EB44A8768581511,
                0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4), 48),
    "sha512": ((0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
                0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
                0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179), 64),
    "sha512_224": ((0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82,
                    0x679DD514582F9FCF, 0x0F6D2B697BD44DA8, 0x77E36F7304C48942,
                    0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1), 28),
    "sha512_256": ((0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151,
                    0x963877195940EABD, 0x96283EE2A88EFFE3, 0xBE5E1E2553863992,
                    0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2), 32),
}


def rotate(value: int, amount: int, width: int) -> int:
    mask = (1 << width) - 1
    return ((value >> amount) | (value << (width - amount))) & mask


def padded(message: bytes, bit_len: int, block_bits: int, length_bits: int) -> bytes:
    bits = [((message[index // 8] >> (7 - index % 8)) & 1) for index in range(bit_len)]
    bits.append(1)
    bits.extend([0] * ((block_bits - length_bits - len(bits)) % block_bits))
    bits.extend((bit_len >> shift) & 1 for shift in range(length_bits - 1, -1, -1))
    output = bytearray(len(bits) // 8)
    for index, bit in enumerate(bits):
        output[index // 8] |= bit << (7 - index % 8)
    return bytes(output)


def digest32(message: bytes, bit_len: int, state: tuple[int, ...], size: int) -> str:
    state = list(state)
    data = padded(message, bit_len, 512, 64)
    for offset in range(0, len(data), 64):
        block = data[offset:offset + 64]
        words = [int.from_bytes(block[index:index + 4], "big") for index in range(0, 64, 4)]
        for index in range(16, 64):
            left = rotate(words[index - 15], 7, 32) ^ rotate(words[index - 15], 18, 32) ^ (words[index - 15] >> 3)
            right = rotate(words[index - 2], 17, 32) ^ rotate(words[index - 2], 19, 32) ^ (words[index - 2] >> 10)
            words.append((words[index - 16] + left + words[index - 7] + right) & MASK32)
        a, b, c, d, e, f, g, h = state
        for constant, word in zip(K32, words):
            choose = (e & f) ^ ((~e) & g)
            majority = (a & b) ^ (a & c) ^ (b & c)
            first = (h + (rotate(e, 6, 32) ^ rotate(e, 11, 32) ^ rotate(e, 25, 32)) + choose + constant + word) & MASK32
            second = ((rotate(a, 2, 32) ^ rotate(a, 13, 32) ^ rotate(a, 22, 32)) + majority) & MASK32
            a, b, c, d, e, f, g, h = (first + second) & MASK32, a, b, c, (d + first) & MASK32, e, f, g
        state = [(old + new) & MASK32 for old, new in zip(state, (a, b, c, d, e, f, g, h))]
    return b"".join(word.to_bytes(4, "big") for word in state).hex()[:size * 2]


def digest64(message: bytes, bit_len: int, state: tuple[int, ...], size: int) -> str:
    state = list(state)
    data = padded(message, bit_len, 1024, 128)
    for offset in range(0, len(data), 128):
        block = data[offset:offset + 128]
        words = [int.from_bytes(block[index:index + 8], "big") for index in range(0, 128, 8)]
        for index in range(16, 80):
            left = rotate(words[index - 15], 1, 64) ^ rotate(words[index - 15], 8, 64) ^ (words[index - 15] >> 7)
            right = rotate(words[index - 2], 19, 64) ^ rotate(words[index - 2], 61, 64) ^ (words[index - 2] >> 6)
            words.append((words[index - 16] + left + words[index - 7] + right) & MASK64)
        a, b, c, d, e, f, g, h = state
        for constant, word in zip(K64, words):
            choose = (e & f) ^ ((~e) & g)
            majority = (a & b) ^ (a & c) ^ (b & c)
            first = (h + (rotate(e, 14, 64) ^ rotate(e, 18, 64) ^ rotate(e, 41, 64)) + choose + constant + word) & MASK64
            second = ((rotate(a, 28, 64) ^ rotate(a, 34, 64) ^ rotate(a, 39, 64)) + majority) & MASK64
            a, b, c, d, e, f, g, h = (first + second) & MASK64, a, b, c, (d + first) & MASK64, e, f, g
        state = [(old + new) & MASK64 for old, new in zip(state, (a, b, c, d, e, f, g, h))]
    return b"".join(word.to_bytes(8, "big") for word in state).hex()[:size * 2]


def oracle(algorithm: str, message: bytes, bit_len: int) -> str:
    state, size = CONFIG[algorithm]
    if algorithm in {"sha224", "sha256"}:
        return digest32(message, bit_len, state, size)
    return digest64(message, bit_len, state, size)


def corpus() -> list[tuple[str, int, bytes, str]]:
    lengths = set(range(0, 33))
    for boundary in (440, 448, 456, 504, 512, 520, 888, 896, 904, 1016, 1024, 1032):
        lengths.update(range(boundary - 7, boundary + 8))
    lengths.update((611, 710, 809, 1123, 1222, 1321, 2047, 2048, 2049, 4095, 4096))
    cases = []
    for algorithm_index, algorithm in enumerate(CONFIG):
        for bit_len in sorted(lengths):
            byte_len = (bit_len + 7) // 8
            value = (0x9E3779B9 ^ bit_len ^ (algorithm_index << 24)) & MASK32
            message = bytearray(byte_len)
            for index in range(byte_len):
                value = (value * 1664525 + 1013904223) & MASK32
                message[index] = value >> 24
            if bit_len % 8 and message:
                message[-1] &= (0xFF << (8 - bit_len % 8)) & 0xFF
            raw = bytes(message)
            cases.append((algorithm, bit_len, raw, oracle(algorithm, raw, bit_len)))
    return cases


def main() -> int:
    cases = corpus()
    requests = "".join(
        f"{algorithm} {bit_len} {message.hex() if message else '-'}\n"
        for algorithm, bit_len, message, _expected in cases
    )
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--locked", "--manifest-path", str(MANIFEST)],
        cwd=ROOT,
        input=requests,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=240,
    )
    if result.returncode != 0:
        raise RuntimeError(f"differential adapter failed:\n{result.stderr}")
    actual = result.stdout.splitlines()
    if len(actual) != len(cases):
        raise RuntimeError("differential adapter returned the wrong result count")
    for index, ((algorithm, bit_len, _message, expected), received) in enumerate(zip(cases, actual)):
        if received != expected:
            raise RuntimeError(f"differential mismatch {index}: {algorithm} at {bit_len} bits")
    malformed = (
        "sha256 1 01\n",
        "sha256 4097 00\n",
        "sha256 999999999999999999999999999999999999 00\n",
        "unknown 0 -\n",
        "sha256 8 -\n",
        " " * 1_201,
    )
    for request in malformed:
        rejected = subprocess.run(
            ["cargo", "run", "--quiet", "--locked", "--manifest-path", str(MANIFEST)],
            cwd=ROOT,
            input=request,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=240,
        )
        if rejected.returncode == 0 or rejected.stdout or "panicked" in rejected.stderr:
            raise RuntimeError(f"adapter accepted malformed request: {request.strip()}")
    print(f"SHA-2 arbitrary-bit differential oracle: PASS ({len(cases)} results, 6 malformed requests rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
