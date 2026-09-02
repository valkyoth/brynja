#!/usr/bin/env python3
"""Import a small, reproducible selection from NIST's FIPS 202 archives."""

from __future__ import annotations

import argparse
import hashlib
import re
import zipfile
from pathlib import Path, PurePosixPath


SHA3_ARCHIVE_SHA256 = "339454bb4b96e299fefcad403797523f1952462a28d2418c108aea30263643ae"
SHAKE_ARCHIVE_SHA256 = "69338cb9cfb1e39b91f54f34bbb82a5d3b0403eb5d77213a669fafed87efebb4"
SHA3_RATES = {"sha3-224": 144, "sha3-256": 136, "sha3-384": 104, "sha3-512": 72}
SHAKE_RATES = {"shake128": 168, "shake256": 136}
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024


def fail(message: str) -> None:
    raise RuntimeError(message)


def archive_members(path: Path, expected_hash: str) -> dict[str, str]:
    data = path.read_bytes()
    if len(data) > MAX_ARCHIVE_BYTES or hashlib.sha256(data).hexdigest() != expected_hash:
        fail(f"untrusted NIST archive: {path}")
    members: dict[str, str] = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = PurePosixPath(info.filename)
            if name.is_absolute() or ".." in name.parts or info.file_size > MAX_MEMBER_BYTES:
                fail(f"unsafe NIST member: {info.filename}")
            if info.is_dir():
                continue
            members[name.name] = archive.read(info).decode("ascii")
    return members


def records(text: str, output_name: str) -> list[tuple[int, int, str, str]]:
    output_bits = 0
    input_bits = 0
    parsed: list[tuple[int, int, str, str]] = []
    current: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        header = re.fullmatch(r"\[Outputlen = (\d+)\]", line)
        if header:
            output_bits = int(header.group(1))
        input_header = re.fullmatch(r"\[Input Length = (\d+)\]", line)
        if input_header:
            input_bits = int(input_header.group(1))
        pair = re.fullmatch(r"(Len|Msg|MD|Output|Outputlen) = ([0-9A-Fa-f]+|\d+)", line)
        if pair:
            current[pair.group(1)] = pair.group(2).lower()
        if output_name in current and "Msg" in current and ("Len" in current or "Outputlen" in current):
            length = int(current.get("Len", str(input_bits)))
            exact_output = int(current.get("Outputlen", str(output_bits)))
            if exact_output == 0:
                exact_output = len(current[output_name]) * 4
            parsed.append((length, exact_output, current["Msg"], current[output_name]))
            current = {}
    return parsed


def select_inputs(algorithm: str, rate: int, parsed: list[tuple[int, int, str, str]]) -> list[str]:
    wanted = {*range(8), rate * 8 - 1, rate * 8}
    chosen = [record for record in parsed if record[0] in wanted]
    found = {record[0] for record in chosen}
    if found != wanted:
        fail(f"missing selected input lengths for {algorithm}: {sorted(wanted - found)}")
    return [f"{algorithm} {length} {output_bits} {message} {output}" for length, output_bits, message, output in chosen]


def select_outputs(algorithm: str, parsed: list[tuple[int, int, str, str]]) -> list[str]:
    selected: dict[int, tuple[int, int, str, str]] = {}
    for record in parsed:
        selected.setdefault(record[1] % 8, record)
    if set(selected) != set(range(8)):
        fail(f"missing output residues for {algorithm}")
    return [
        f"{algorithm} {length} {output_bits} {message} {output}"
        for _residue, (length, output_bits, message, output) in sorted(selected.items())
    ]


def build(sha3_archive: Path, shake_archive: Path) -> str:
    sha3 = archive_members(sha3_archive, SHA3_ARCHIVE_SHA256)
    shake = archive_members(shake_archive, SHAKE_ARCHIVE_SHA256)
    lines = [
        "# NIST CAVP FIPS 202 curated bit vectors; low-bit partial-byte packing.",
        f"# sha-3bittestvectors.zip sha256={SHA3_ARCHIVE_SHA256}",
        f"# shakebittestvectors.zip sha256={SHAKE_ARCHIVE_SHA256}",
        "# algorithm input_bits output_bits input_hex output_hex",
    ]
    for algorithm, rate in SHA3_RATES.items():
        prefix = algorithm.upper().replace("-", "_")
        source = records(sha3[prefix + "ShortMsg.rsp"], "MD")
        source.extend(records(sha3[prefix + "LongMsg.rsp"], "MD"))
        lines.extend(select_inputs(algorithm, rate, source))
    for algorithm, rate in SHAKE_RATES.items():
        prefix = algorithm.upper()
        source = records(shake[prefix + "ShortMsg.rsp"], "Output")
        source.extend(records(shake[prefix + "LongMsg.rsp"], "Output"))
        lines.extend(select_inputs(algorithm, rate, source))
        lines.extend(select_outputs(algorithm, records(shake[prefix + "VariableOut.rsp"], "Output")))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sha3_archive", type=Path)
    parser.add_argument("shake_archive", type=Path)
    parser.add_argument("--write", type=Path)
    args = parser.parse_args()
    rendered = build(args.sha3_archive, args.shake_archive)
    if args.write is None:
        print(rendered, end="")
    else:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(rendered, encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
