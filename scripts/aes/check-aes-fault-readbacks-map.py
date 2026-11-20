#!/usr/bin/env python3
"""Observe paired guarded-write checks in pinned development test ELFs.

Public-route destination and secret-route staging are distinct. Read-only
public-fixture observations here do not qualify either check against faults.
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
    "result_map", Path(__file__).with_name("check-aes-fault-result-map.py"))
RESULT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESULT)
RETAINED = RESULT.RETAINED
GUARDED = "brynja_crypto::aes::fault_integrity::transaction::guarded_write"
CHECK = "brynja_crypto::aes::fault_integrity::transaction::check"
SHAPES = {
    "a11c368e8eccec0e497d336ebe6a9de6381a01dfd3716887c8d69b84efa69c26": {
        "toolchain": "1.90.0", "guarded_address": 0x10c050, "check_address": 0x10c3f0,
        "call_offsets": (0x1cb, 0x1e6), "flag_offsets": (0x1c8, 0x1e0),
    },
    "bf61f409964ce7678b2a5694e63a5640d4b0a320c76d76866b25c9e95a307baf": {
        "toolchain": "1.100.0", "guarded_address": 0xd0d80, "check_address": 0xd0fd0,
        "call_offsets": (0x147, 0x162), "flag_offsets": (0x144, 0x15c),
    },
}


def inspect(dump, shape):
    header = re.compile(r"\s*([0-9a-f]+) <(.+)>:\s*")
    instruction = re.compile(r"\s*([0-9a-f]+):\s+(.+?)\s*")
    body, selected, found = {}, False, 0
    for line in dump.splitlines():
        match = header.fullmatch(line)
        if match:
            selected = match[2] == GUARDED
            if selected:
                found += 1
                if int(match[1], 16) != shape["guarded_address"]:
                    raise ValueError("unreviewed guarded-write address")
        elif selected and line.strip():
            op = instruction.fullmatch(line)
            if not op:
                raise ValueError("unparsed guarded-write instruction")
            body[int(op[1], 16) - shape["guarded_address"]] = re.sub(
                r"\s+", " ", op[2]).replace(", ", ",")
    if found != 1:
        raise ValueError("missing or ambiguous guarded-write function")
    for offset in shape["call_offsets"]:
        if body.get(offset) != f"call {shape['check_address']:x} <{CHECK}>":
            raise ValueError("unreviewed guarded-write check call")
    first_flag, second_flag = shape["flag_offsets"]
    if body.get(first_flag) != "xor %r8d,%r8d":
        raise ValueError("unreviewed forward-check selector")
    if body.get(second_flag) != "mov $0x1,%r8d":
        raise ValueError("unreviewed reverse-check selector")
    if sum(op.endswith("<" + CHECK + ">") for op in body.values()) != 2:
        raise ValueError("unreviewed check call multiplicity")


def commands(shape, answer):
    first, second = shape["call_offsets"]
    address = lambda offset: f"((unsigned long long)&'{GUARDED}'+{offset})"
    values = lambda pointer: RESULT.equal_words(pointer, answer)
    return [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *('{GUARDED}'+{first})",
        f"hbreak *('{GUARDED}'+{second})", "disable 2", "continue",
        "set $checked=(unsigned char*)$rdi",
        "set $primary=(unsigned char*)$rdx",
        "set $secondary=(unsigned char*)$rcx",
        'printf "READBACK_FORWARD %d\\n", '
        f"($rsi == 16 && $r8 == 0 && $checked != $primary && "
        f"$checked != $secondary && $primary != $secondary && "
        f"{values('$checked')} && {values('$primary')} && {values('$secondary')})",
        "disable 1", "nexti",
        'printf "READBACK_FORWARD_DONE %d\\n", '
        f"($pc == {address(first + 5)} && $al == 0)",
        "enable 2", "continue",
        'printf "READBACK_REVERSE %d\\n", '
        f"($rsi == 16 && $r8 == 1 && (unsigned char*)$rdi == $checked && "
        f"(unsigned char*)$rdx == $primary && (unsigned char*)$rcx == $secondary && "
        f"{values('$checked')} && {values('$primary')} && {values('$secondary')})",
        "disable 2", "nexti",
        'printf "READBACK_REVERSE_DONE %d\\n", '
        f"($pc == {address(second + 5)} && $al == 0)",
        "continue",
    ]


def validate_output(output, width, owner, path):
    if re.findall(r"^READBACK_[^\r\n]*", output, re.M) != [
        "READBACK_FORWARD 1", "READBACK_FORWARD_DONE 1",
        "READBACK_REVERSE 1", "READBACK_REVERSE_DONE 1",
    ]:
        raise ValueError("paired readback boundary or answer unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", output, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
    ]:
        raise ValueError("readback baseline identity or outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 2
            or output.count("hit Breakpoint ") != 2
            or RETAINED.identity(width, owner, path) not in output
            or output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or output.count("exited normally") != 1):
        raise ValueError("readback baseline execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    shape = SHAPES.get(digest)
    if shape is None:
        raise ValueError("unreviewed readback artifact")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    inspect(dump, shape)
    cases = []
    for width in RETAINED.WIDTHS:
        for owner in RETAINED.OWNERS:
            for path in RETAINED.PATHS:
                answer = RESULT.PLAIN if path == "decrypt" else RESULT.CIPHERS[width]
                argv = [gdb, "-q", "-nx", "-batch"]
                for command in commands(shape, answer):
                    argv += ["-ex", command]
                argv += ["--args", str(binary), "--exact",
                         RETAINED.identity(width, owner, path), "--nocapture"]
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate_output(run.stdout + run.stderr, width, owner, path)
                cases.append(f"aes{width * 8}/{owner}/{path}")
    if binary.read_bytes() != original or len(cases) != 18:
        raise ValueError("artifact changed or readback baseline incomplete")
    return {
        "schema": 1, "status": "development-guarded-write-readbacks-observed",
        "qualification": "none", "arch": "x86_64", "toolchain": shape["toolchain"],
        "binary_sha256": digest, "guarded_symbol": GUARDED, "check_symbol": CHECK,
        "call_offsets": list(shape["call_offsets"]),
        "selector_offsets": list(shape["flag_offsets"]), "baseline_cases": cases,
        "limits": [
            "Public-fixture primitive-only test ELF; not a production or admitted build.",
            "Public route checks its actual destination; secret route checks private staging here.",
            "The later actual secret-destination check, check internals and failure branches remain unmapped.",
            "No bypass, mutation, DC1 pairing or physical fault was tested.",
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
        print("Readback mapping failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Paired guarded-write checks mapped; 18 baselines; no mutations.")
        print("DEVELOPMENT_MAPPING_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
