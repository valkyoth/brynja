#!/usr/bin/env python3
"""HMAC bit messages using separate Python hash models; no runtime dependency."""
import hashlib
import hmac
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ALGORITHMS = ("sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256",
              "sha3_224", "sha3_256", "sha3_384", "sha3_512")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SHA2 = load("hmac_sha2_bit_model", "scripts/sha2/check-sha2-bit-differential.py")
SHA3 = load("hmac_sha3_bit_model", "scripts/sha3/check-sha3-bit-differential.py")


def digest(algorithm, message, bits):
    if algorithm.startswith("sha3_"):
        return SHA3.keccak(algorithm.replace("_", "-"), message, bits,
                           hashlib.new(algorithm).digest_size * 8)
    state, size = SHA2.CONFIG[algorithm]
    function = SHA2.digest32 if algorithm in ("sha224", "sha256") else SHA2.digest64
    return bytes.fromhex(function(message, bits, state, size))


def authenticate(algorithm, key, message, bits):
    block = hashlib.new(algorithm).block_size
    normalized = digest(algorithm, key, len(key) * 8) if len(key) > block else key
    pad = normalized.ljust(block, b"\0")
    inner_input = bytes(value ^ 0x36 for value in pad) + message
    inner = digest(algorithm, inner_input, block * 8 + bits)
    outer_input = bytes(value ^ 0x5c for value in pad) + inner
    return digest(algorithm, outer_input, len(outer_input) * 8)


def rows():
    output = []
    for algorithm in ALGORITHMS:
        block = hashlib.new(algorithm).block_size
        lengths = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16,
                   (block - 17) * 8 - 1, (block - 9) * 8 - 1,
                   block * 8 - 9, block * 8 - 7, block * 8 - 6,
                   block * 8 - 5, block * 8 - 4, block * 8 - 3,
                   block * 8 - 2, block * 8 - 1, block * 8,
                   block * 8 + 1, block * 8 + 7, block * 16 + 3)
        if len(set(lengths)) != 26:
            raise ValueError("bit-boundary population changed")
        for key_size in (0, block, block + 1, block * 2 + 1):
            key = bytes((index * 29 + 7) % 256 for index in range(key_size))
            for bits in lengths:
                message = bytearray((index * 131 + 17) % 256 for index in range((bits + 7) // 8))
                if bits % 8:
                    message[-1] &= ((1 << (bits % 8)) - 1 if algorithm.startswith("sha3_")
                                    else (0xff << (8 - bits % 8)) & 0xff)
                expected = authenticate(algorithm, key, bytes(message), bits)
                if bits % 8 == 0 and expected != hmac.new(key, message, algorithm).digest():
                    raise ValueError("Python bit model disagrees with Python/OpenSSL HMAC control")
                output.append(":".join((algorithm, key.hex(), message.hex(), str(bits), expected.hex())))
    if len(output) != 1040:
        raise ValueError("HMAC bit oracle population drift")
    return output


def main():
    with tempfile.TemporaryDirectory(prefix="brynja-hmac-bit-oracle-") as directory:
        path = Path(directory) / "oracle.txt"
        path.write_text("\n".join(rows()) + "\n", encoding="ascii")
        env = os.environ.copy()
        env["BRYNJA_HMAC_BIT_ORACLE"] = str(path)
        result = subprocess.run(
            ["cargo", "test", "-p", "brynja-mac-hmac", "--locked", "--offline",
             "--test", "bit_differential", "--", "--ignored", "--exact", "external_bit_oracle", "--nocapture"],
            cwd=ROOT, env=env, check=True, text=True, capture_output=True, timeout=300,
        )
        marker = "HMAC_BIT_ORACLE: 1040 cases; 10 algorithms; bit finalization and truncated verification"
        if (marker not in result.stdout.splitlines()
                or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in result.stdout):
            raise RuntimeError("missing HMAC bit oracle population")
        print(result.stdout, end="")


if __name__ == "__main__":
    main()
