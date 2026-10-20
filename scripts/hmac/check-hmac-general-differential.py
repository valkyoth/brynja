#!/usr/bin/env python3
"""All policy-admitted SHA-512/t HMAC parameters, separate Python hash model."""
import hmac
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "scripts/sha2"))
import sha512_t_digest_oracle as model


def authenticate(t, key, message, bits):
    normalized = model.digest(t, key, len(key) * 8) if len(key) > 128 else key
    pad = normalized.ljust(128, b"\0")
    inner = model.digest(t, bytes(value ^ 0x36 for value in pad) + message, 1024 + bits)
    # The inner result is t bits, NOT ceil(t/8) whole bytes.
    return model.digest(t, bytes(value ^ 0x5c for value in pad) + inner, 1024 + t)


def rows():
    model.iv.render()  # Independently derived constants and OpenSSL SHA-512 controls.
    output = []
    for t in range(128, 512):
        if t == 384:
            continue
        for key_size in (0, 128, 129, 257):
            key = bytes((index * 29 + 7) % 256 for index in range(key_size))
            for bits in (0, 24, 1023, 1031):
                message = bytearray((index * 131 + 17) % 256 for index in range((bits + 7) // 8))
                if bits % 8:
                    message[-1] &= (0xff << (8 - bits % 8)) & 0xff
                expected = authenticate(t, key, bytes(message), bits)
                if t in (224, 256) and bits % 8 == 0:
                    if expected != hmac.new(key, message, f"sha512_{t}").digest():
                        raise ValueError("general HMAC model disagrees with named OpenSSL control")
                output.append(":".join((str(t), key.hex(), message.hex(), str(bits), expected.hex())))
    if len(output) != 6128:
        raise ValueError("general HMAC oracle population drift")
    return output


def main():
    with tempfile.TemporaryDirectory(prefix="brynja-hmac-general-oracle-") as directory:
        path = Path(directory) / "oracle.txt"
        path.write_text("\n".join(rows()) + "\n", encoding="ascii")
        env = os.environ.copy()
        env["BRYNJA_HMAC_GENERAL_ORACLE"] = str(path)
        result = subprocess.run(
            ["cargo", "test", "-p", "brynja-mac-hmac", "--locked", "--offline",
             "--test", "general_differential", "--", "--ignored", "--exact",
             "external_general_oracle", "--nocapture"],
            cwd=ROOT, env=env, check=True, text=True, capture_output=True, timeout=300,
        )
        marker = "HMAC_GENERAL_ORACLE: 6128 cases; 383 parameters; exact-bit inner and outer messages"
        if (marker not in result.stdout.splitlines()
                or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in result.stdout):
            raise RuntimeError("missing general HMAC oracle population")
        print(result.stdout, end="")


if __name__ == "__main__":
    main()
