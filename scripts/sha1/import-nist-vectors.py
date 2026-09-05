#!/usr/bin/env python3
"""Import a reproducible SHA-1 selection from the pinned official CAVP archive."""

import argparse
import hashlib
import re
import subprocess
import zipfile
from pathlib import Path

ARCHIVE_SHA256 = "cd7b9f11680c6e0ccdbe13b28403f2017b5ff48789152162461e0a24fb4c5d45"
ROOT = Path(__file__).resolve().parents[2]
TARGET = "crates/brynja-legacy-sha1/tests/vectors/nist.txt"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    if hashlib.sha256(args.archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("official archive checksum differs")
    lines = ["# NIST CAVP shabittestvectors.zip; bit length | canonical message hex | digest",
             f"# archive SHA-256: {ARCHIVE_SHA256}"]
    with zipfile.ZipFile(args.archive) as archive:
        for name in ("SHA1ShortMsg.rsp", "SHA1LongMsg.rsp"):
            text = archive.read("shabittestvectors/" + name).decode("ascii")
            records = re.findall(r"Len = (\d+)\s+Msg = ([0-9a-fA-F]+)\s+MD = ([0-9a-fA-F]+)", text)
            if name == "SHA1LongMsg.rsp":
                records = records[:16]
            for bits, message, digest in records:
                length = int(bits)
                data = bytearray.fromhex(message)[:(length + 7) // 8]
                if length % 8:
                    data[-1] &= (0xff << (8 - length % 8)) & 0xff
                lines.append(f"{length}|{data.hex() or '-'}|{digest.lower()}")
    content = "\n".join(lines) + "\n"
    target = ROOT / TARGET
    if target.exists():
        if target.read_text() != content:
            raise ValueError("committed vector selection differs")
    else:
        patch = f"*** Begin Patch\n*** Add File: {TARGET}\n"
        patch += "".join("+" + line + "\n" for line in content.splitlines())
        subprocess.run(["apply_patch", patch + "*** End Patch\n"], cwd=ROOT, check=True)
    print(f"official SHA-1 vector selection: {len(lines) - 2} records")


if __name__ == "__main__":
    main()
