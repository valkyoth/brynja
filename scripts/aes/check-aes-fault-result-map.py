#!/usr/bin/env python3
"""Observe two AES result boundaries in pinned development test ELFs.

This read-only public-vector probe does not inject faults or qualify D1.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys


SPEC = importlib.util.spec_from_file_location(
    "retained_map", Path(__file__).with_name("check-aes-fault-retained-validation-map.py"))
RETAINED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RETAINED)
PLAIN = bytes.fromhex("00112233445566778899aabbccddeeff")
CIPHERS = {
    16: bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
    24: bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191"),
    32: bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"),
}
PRIMARY_RETURN = 0xcb
SECONDARY_RETURN = 0xe2
PRIMARY_CALLS = {16: 0xb8, 24: 0xaa, 32: 0xc6}
SECONDARY_CALL = 0xdd


def inspect(dump, shape):
    symbol = shape["compute"]
    header = re.compile(r"\s*([0-9a-f]+) <(.+)>:\s*")
    instruction = re.compile(r"\s*([0-9a-f]+):\s+(.+?)\s*")
    body, selected, found = {}, False, 0
    for line in dump.splitlines():
        match = header.fullmatch(line)
        if match:
            selected = match[2] == symbol
            if selected:
                found += 1
                if int(match[1], 16) != shape["compute_address"]:
                    raise ValueError("unreviewed result compute address")
        elif selected and line.strip():
            op = instruction.fullmatch(line)
            if not op:
                raise ValueError("unparsed result compute instruction")
            body[int(op[1], 16) - shape["compute_address"]] = re.sub(
                r"\s+", " ", op[2]).replace(", ", ",")
    if found != 1:
        raise ValueError("missing or ambiguous result compute function")
    if body.get(0x12) != "mov %rcx,%r15" or body.get(0x15) != "mov %rdx,%r12":
        raise ValueError("unreviewed result pointer provenance")
    for width, offset in PRIMARY_CALLS.items():
        op = body.get(offset, "")
        if not op.startswith("call ") or "portable::" not in op or "transform" not in op:
            raise ValueError(f"unreviewed primary transform for {width}")
        if body.get(offset - 3) != "mov %r12,%rdi":
            raise ValueError("unreviewed primary result pointer")
    if body.get(PRIMARY_RETURN) != "test %al,%al":
        raise ValueError("unreviewed primary return boundary")
    secondary = body.get(SECONDARY_CALL, "")
    if not (secondary.startswith("call ") and "schedule::Schedule" in secondary
            and "::transform" in secondary):
        raise ValueError("unreviewed secondary transform")
    if body.get(SECONDARY_CALL - 3) != "mov %r15,%rdx":
        raise ValueError("unreviewed secondary result pointer")
    if body.get(SECONDARY_RETURN) != "test %al,%al":
        raise ValueError("unreviewed secondary return boundary")
    if shape["validate"] not in body.get(0xe9, ""):
        raise ValueError("post-use validation no longer follows result boundaries")


def equal_words(pointer, expected):
    parts = [f"(*(unsigned int*)({pointer}+{offset}) == "
             f"0x{int.from_bytes(expected[offset:offset + 4], 'little'):08x}U)"
             for offset in range(0, 16, 4)]
    return " && ".join(parts)


def commands(shape, expected):
    symbol = shape["compute"]
    address = lambda offset: f"((unsigned long long)&'{symbol}'+{offset})"
    return [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *('{symbol}'+{PRIMARY_RETURN})",
        f"hbreak *('{symbol}'+{SECONDARY_RETURN})", "disable 2", "continue",
        "printf \"RESULT_PRIMARY %d\\n\", "
        f"($pc == {address(PRIMARY_RETURN)} && $al == 0 && "
        f"{equal_words('(unsigned char*)$r12', expected)})",
        "disable 1", "enable 2", "continue",
        "printf \"RESULT_SECONDARY %d\\n\", "
        f"($pc == {address(SECONDARY_RETURN)} && $al == 0 && "
        f"{equal_words('(unsigned char*)$r15', expected)})",
        "disable 2", "continue",
    ]


def validate_output(output, width, owner, path):
    if re.findall(r"^RESULT_[^\r\n]*", output, re.M) != [
        "RESULT_PRIMARY 1", "RESULT_SECONDARY 1"
    ]:
        raise ValueError("result boundaries or public answers unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", output, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
    ]:
        raise ValueError("result baseline identity or outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 2
            or output.count("hit Breakpoint ") != 2
            or RETAINED.identity(width, owner, path) not in output
            or output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or output.count("exited normally") != 1):
        raise ValueError("result baseline execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    shape = RETAINED.SHAPES.get(digest)
    if shape is None:
        raise ValueError("unreviewed result artifact")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    inspect(dump, shape)
    cases = []
    for width in RETAINED.WIDTHS:
        for owner in RETAINED.OWNERS:
            for path in RETAINED.PATHS:
                expected = PLAIN if path == "decrypt" else CIPHERS[width]
                argv = [gdb, "-q", "-nx", "-batch"]
                for command in commands(shape, expected):
                    argv += ["-ex", command]
                argv += ["--args", str(binary), "--exact",
                         RETAINED.identity(width, owner, path), "--nocapture"]
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate_output(run.stdout + run.stderr, width, owner, path)
                cases.append(f"aes{width * 8}/{owner}/{path}")
    if binary.read_bytes() != original or len(cases) != 18:
        raise ValueError("artifact changed or result baseline incomplete")
    return {
        "schema": 1, "status": "development-result-boundaries-observed",
        "qualification": "none", "arch": "x86_64", "toolchain": shape["toolchain"],
        "binary_sha256": digest, "compute_symbol": shape["compute"],
        "primary_call_offsets": {str(k): v for k, v in PRIMARY_CALLS.items()},
        "primary_return_offset": PRIMARY_RETURN, "secondary_call_offset": SECONDARY_CALL,
        "secondary_return_offset": SECONDARY_RETURN, "baseline_cases": cases,
        "limits": [
            "Public-fixture primitive-only test ELF; not a production or admitted build.",
            "Only successful result-boundary values and transform order were observed.",
            "No result mutation, D1 detection, DC1 bypass pairing or physical fault was tested.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        report = observe(args.binary, args.objdump, args.gdb)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print("Result mapping failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Primary/secondary result boundaries mapped; 18 baselines; no mutations.")
        print("DEVELOPMENT_MAPPING_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
