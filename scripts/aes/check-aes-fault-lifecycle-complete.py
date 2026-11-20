#!/usr/bin/env python3
"""Finite lifecycle-completion byte-fault experiment on pinned test ELFs.

Trusted local binaries and public FIPS fixtures only. A debugger mutates one
in-progress codeword byte; this is not physical, bypass or release evidence.
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
    "secret_caller_map", Path(__file__).with_name("check-aes-fault-secret-caller-map.py"))
CALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CALLER)
RESULT_MAP = CALLER.RESULT_MAP
DEST = CALLER.DEST
RESULT = CALLER.RESULT
RETAINED = CALLER.RETAINED


def commands(owner, local, caller, answer, byte=0, bit=0):
    if not (type(byte) is int and 0 <= byte < 16 and
            type(bit) is int and 0 <= bit < 8):
        raise ValueError("invalid lifecycle byte/bit position")
    changed = 0x3c ^ (1 << bit)
    expected = bytearray([0x3c] * 16)
    expected[byte] = changed
    first = int.from_bytes(expected[:8], "little")
    second = int.from_bytes(expected[8:], "little")
    mutation = (f"set {{unsigned char}}$state = 0x{changed:02x}" if byte == 0
                else f"set {{unsigned char}}($state+{byte}) = 0x{changed:02x}")
    symbol = owner["symbol"]
    complete = f"((unsigned long long)&'{symbol}'+{local['complete']})"
    return [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *'{symbol}'",
        f"hbreak *('{symbol}'+{local['complete']})", "disable 2",
        f"hbreak *('{caller['symbol']}'+{caller['call']}+5)", "disable 3",
        "continue", "set $output=(unsigned char*)$rcx",
        "set $result=(unsigned char*)$rdi", "disable 1", "enable 2", "continue",
        "set $state=(unsigned char*)$rdi",
        'printf "LIFECYCLE_PRE %d\\n", '
        f"($pc == {complete} && $output != 0 && $result != 0 && "
        f"{DEST.same_word('$state', 0x3c3c3c3c3c3c3c3c)} && "
        f"{RESULT.equal_words('$output', answer)})",
        mutation,
        'printf "LIFECYCLE_MUTATED %d\\n", '
        f"(*(unsigned long long*)$state == 0x{first:016x}ULL && "
        f"*(unsigned long long*)($state+8) == 0x{second:016x}ULL)",
        "disable 2", "nexti",
        'printf "LIFECYCLE_REJECTED %d\\n", '
        f"($pc == {complete}+5 && $al != 0)",
        "enable 3", "continue",
        'printf "LIFECYCLE_CALLER %d\\n", '
        f"({DEST.same_word('$state', 0xc3c3c3c3c3c3c3c3)} && "
        f"{DEST.same_word('$output', 0)} && *(unsigned char*)$result != 0)",
        "disable 3", "continue",
    ]


def validate_output(output, width, owner, path):
    if re.findall(r"^LIFECYCLE_[^\r\n]*", output, re.M) != [
        "LIFECYCLE_PRE 1", "LIFECYCLE_MUTATED 1",
        "LIFECYCLE_REJECTED 1", "LIFECYCLE_CALLER 1",
    ]:
        raise ValueError("lifecycle-completion fault boundary unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", output, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_REJECTED_RETIRED",
    ]:
        raise ValueError("lifecycle-completion fixture outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 3
            or output.count("hit Breakpoint ") != 3
            or RETAINED.identity(width, owner, path) not in output
            or output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or output.count("exited normally") != 1):
        raise ValueError("lifecycle-completion execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    owner_shape = DEST.SHAPES.get(digest)
    result_shape = RESULT_MAP.SHAPES.get(digest)
    caller_shape = CALLER.SHAPES.get(digest)
    if owner_shape is None or result_shape is None or caller_shape is None:
        raise ValueError("unreviewed lifecycle-completion artifact")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    RESULT_MAP.inspect(dump, result_shape, owner_shape)
    CALLER.inspect(dump, caller_shape, owner_shape)
    cases = []
    for width in RETAINED.WIDTHS:
        for owner in RETAINED.OWNERS:
            for path in ("encrypt", "decrypt"):
                answer = RESULT.PLAIN if path == "decrypt" else RESULT.CIPHERS[width]
                argv = [gdb, "-q", "-nx", "-batch"]
                for command in commands(owner_shape["owners"][owner],
                                        result_shape["owners"][owner],
                                        caller_shape["callers"][owner], answer):
                    argv += ["-ex", command]
                argv += ["--args", str(binary), "--exact",
                         RETAINED.identity(width, owner, path), "--nocapture"]
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate_output(run.stdout + run.stderr, width, owner, path)
                cases.append(f"aes{width * 8}/{owner}/{path}")
    if binary.read_bytes() != original or len(cases) != 12:
        raise ValueError("artifact changed or lifecycle-completion cases incomplete")
    return {
        "schema": 1, "status": "development-lifecycle-completion-byte-mutation-observed",
        "qualification": "none", "arch": "x86_64", "toolchain": owner_shape["toolchain"],
        "binary_sha256": digest, "mutation": "in-progress-first-byte-0x3c-to-0x3d",
        "owner_complete_offsets": {owner: local["complete"]
                                   for owner, local in result_shape["owners"].items()},
        "fixture_return_offsets": {owner: local["call"] + 5
                                   for owner, local in caller_shape["callers"].items()},
        "observed_cases": cases,
        "limits": [
            "One selected codeword byte change per public-fixture operation; no bypass pairing.",
            "Debugger mutation in a test ELF, not a physical or production fault model.",
            "The fixture checks cleared output, terminal owner and rejected reuse.",
            "No complete lifecycle-handoff qualification or public admission.",
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
        print("Lifecycle-completion probe failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Lifecycle-completion byte mutation rejected; 12 cases in pinned ELF.")
        print("DEVELOPMENT_PROBE_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
