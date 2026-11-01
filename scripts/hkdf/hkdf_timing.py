"""Strict synthetic HKDF populations and independent HMAC-based preflight."""
import hmac
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hmac"))
from hmac_timing import SAMPLES, LIMIT, screen

WIDTHS = {"sha224": 28, "sha256": 32, "sha384": 48, "sha512": 64,
          "sha512_224": 28, "sha512_256": 32}
MODES = ("extract-ikm", "extract-salt", "import-long", "expand", "expand-long", "label")


def population(family):
    if family not in ("modern", "legacy"):
        raise ValueError("unknown timing family")
    widths = WIDTHS if family == "modern" else {"sha1": 20}
    return [(identity, width, mode) for identity, width in widths.items()
            for mode in (MODES if family == "modern" else MODES[:-1])]


def answer(identity, width, mode, secret):
    if mode == "extract-ikm":
        return hmac.digest(b"\x37" * 32, secret[:64], identity)
    if mode == "extract-salt":
        return hmac.digest(secret, b"\x37" * 64, identity)
    if mode == "import-long":
        return secret
    key = secret if mode == "expand-long" else secret[:width]
    length = 2 * width + 7
    info = b"\x37" * 48
    if mode == "label":
        info = length.to_bytes(2, "big") + b"\x09tls13 key\x30" + info
    elif mode not in ("expand", "expand-long"):
        raise ValueError("unknown oracle operation")
    return expand(identity, key, info, length)


def expand(identity, key, info, length):
    width = len(hmac.digest(key, b"", identity))
    if not 0 <= length <= 255 * width:
        raise ValueError("oracle output bound")
    output = b""
    block = b""
    for counter in range(1, (length + width - 1) // width + 1):
        block = hmac.digest(key, block + info + bytes([counter]), identity)
        output += block
    return output[:length]


def preflight(text, family):
    expected = []
    for identity, width, mode in population(family):
        for cls in (0, 1):
            value = answer(identity, width, mode, bytes([0xff if cls else 0]) * 200)
            expected.append(f"VECTOR {identity} {mode} {cls} {value.hex()}")
    if text.splitlines() != [*expected, "HKDF_TIMING_END preflight"]:
        raise ValueError("HKDF timing correctness preflight failed")


def parse(text, family):
    lines = text.splitlines()
    campaigns = population(family)
    if len(lines) != len(campaigns) * SAMPLES + 1 or lines[-1] != "HKDF_TIMING_END measure":
        raise ValueError("timing population or completion changed")
    rows = []
    cursor = 0
    for identity, width, mode in campaigns:
        pairs = []
        for sample in range(SAMPLES):
            fields = lines[cursor].split()
            cursor += 1
            if len(fields) != 6 or fields[:4] != ["SAMPLE", identity, mode, str(sample)]:
                raise ValueError("timing identity/order changed")
            if any(not re.fullmatch(r"[1-9][0-9]{0,18}", value) for value in fields[4:]):
                raise ValueError("invalid timing value")
            pairs.append(tuple(int(value) for value in fields[4:]))
        rows.append({"identity": identity, "digest_bytes": width, "mode": mode, **screen(pairs)})
    return rows
