"""Bounded all-parameter independent byte/bit corpus, not runtime crypto."""
import argparse
import hashlib
from pathlib import Path
import sha512_t_iv_oracle as iv

CORPUS = iv.ROOT / "crates/brynja-hash-sha2/tests/vectors/general-sha512-t-digest.txt"


def digest(t, message, bits):
    initial = iv.hash_bytes(f"SHA-512/{t}".encode(), [w ^ 0xa5a5a5a5a5a5a5a5 for w in iv.INITIAL])
    words = iv.hash_bytes(message, initial, bits)
    result = bytearray(b"".join(w.to_bytes(8, "big") for w in words)[:(t + 7) // 8])
    if t % 8:
        result[-1] &= (0xff << (8 - t % 8)) & 0xff
    return bytes(result)


def render():
    iv.render()  # Independently derived constants and named IV controls.
    rows = []
    for t in range(1, 512):
        if t == 384:
            continue
        messages = [(b"", 0), (b"abc", 24)]
        for width, size in enumerate((111, 112, 127, 128, 129, 255, 256), 1):
            message = bytes(i % 251 for i in range(size)) + bytes([0xa5 & (0xff << (8 - width))])
            messages.append((message, size * 8 + width))
        for message, bits in messages:
            result = digest(t, message, bits)
            if t in (224, 256) and bits % 8 == 0:
                if result != hashlib.new(f"sha512_{t}", message).digest():
                    raise ValueError("named OpenSSL cross-check differs")
            rows.append(f"{t} {bits} {message.hex() or '-'} {result.hex()}")
    return ("\n".join(rows) + "\n").encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.write:
        CORPUS.write_bytes(expected)
    with CORPUS.open("rb") as stream:
        actual = stream.read(3_000_001).replace(b"\r\n", b"\n")
    if actual != expected:
        raise ValueError("digest corpus differs from independent oracle")
    print("General SHA-512/t digest oracle: 4590 byte/bit cases, all 510 parameters PASS")


if __name__ == "__main__":
    main()
