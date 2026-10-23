"""Separate Python bit-hash models, controlled against stdlib byte HMAC."""
import hashlib
import hmac
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LENGTHS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 447, 448, 449, 503, 504, 505,
           511, 512, 513, 1023, 1024, 1025)


def model(name):
    folder = "sha1" if name == "sha1" else "md5"
    path = ROOT / f"scripts/{folder}/check-{folder}-differential.py"
    spec = importlib.util.spec_from_file_location("legacy_hmac_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return lambda message, bits: bytes.fromhex(module.oracle(message, bits))


def expected():
    rows = {}
    for name in ("md5", "sha1"):
        digest = model(name)
        for length in (0, 64, 65, 129):
            key = bytes([0xa7]) * length
            normalized = digest(key, length * 8) if length > 64 else key
            pad = normalized.ljust(64, b"\0")
            for bits in LENGTHS:
                message = bytearray([0xa5] * ((bits + 7) // 8))
                if bits % 8:
                    message[-1] &= (0xff << (8 - bits % 8)) & 0xff
                inner = digest(bytes(b ^ 0x36 for b in pad) + message, 512 + bits)
                outer = bytes(b ^ 0x5c for b in pad) + inner
                tag = digest(outer, len(outer) * 8)
                if bits % 8 == 0 and tag != hmac.new(key, message, getattr(hashlib, name)).digest():
                    raise ValueError("legacy bit model disagrees with independent byte control")
                rows[f"{name}:{length}:{bits}"] = tag.hex()
    if len(rows) != 176:
        raise ValueError("legacy bit oracle population changed")
    return rows


def validate(output):
    actual = {}
    for line in output.splitlines():
        identity, tag = line.rsplit(":", 1)
        if identity in actual:
            raise ValueError("duplicate legacy bit oracle identity")
        actual[identity] = tag
    if actual != expected():
        raise ValueError("legacy bit oracle mismatch or missing population")
