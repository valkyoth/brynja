#!/usr/bin/env python3
"""Observe inner-to-outer completion handoff in pinned development ELFs.

Read-only public-fixture breakpoints; no mutations or fault qualification.
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
    "completion_map", Path(__file__).with_name("check-aes-fault-completion-map.py"))
INNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INNER)
RETAINED = INNER.RETAINED
EPHEMERAL = "brynja_crypto::aes::fault_integrity::retained::ephemeral::Ephemeral"
SHAPES = {
    "a11c368e8eccec0e497d336ebe6a9de6381a01dfd3716887c8d69b84efa69c26": {
        "toolchain": "1.90.0", "symbol": EPHEMERAL + "::compute",
        "address": 0x108d30, "inner_call": 0x35f, "outer_load": 0x821,
        "outer_store": 0x82e,
    },
    "bf61f409964ce7678b2a5694e63a5640d4b0a320c76d76866b25c9e95a307baf": {
        "toolchain": "1.100.0", "symbol": "<" + EPHEMERAL + ">::compute",
        "address": 0xc2e90, "inner_call": 0x25e, "outer_load": 0x507,
        "outer_store": 0x50f,
    },
}


def inspect(dump, retained, outer):
    INNER.inspect(dump, retained)
    header = re.compile(r"\s*([0-9a-f]+) <(.+)>:\s*")
    instruction = re.compile(r"\s*([0-9a-f]+):\s+(.+?)\s*")
    body, selected, found = {}, False, 0
    for line in dump.splitlines():
        match = header.fullmatch(line)
        if match:
            selected = match[2] == outer["symbol"]
            if selected:
                found += 1
                if int(match[1], 16) != outer["address"]:
                    raise ValueError("unreviewed outer compute address")
        elif selected and line.strip():
            op = instruction.fullmatch(line)
            if not op:
                raise ValueError("unparsed outer compute instruction")
            body[int(op[1], 16) - outer["address"]] = re.sub(
                r"\s+", " ", op[2]).replace(", ", ",")
    if found != 1:
        raise ValueError("missing or ambiguous outer compute function")
    call = outer["inner_call"]
    if not body.get(call, "").endswith("<" + retained["compute"] + ">"):
        raise ValueError("unreviewed inner compute call")
    if body.get(call + 5) != "test %al,%al":
        raise ValueError("unreviewed inner completion return")
    if not body.get(call + 7, "").startswith("jne "):
        raise ValueError("unreviewed inner failure branch")
    if not body.get(outer["outer_load"], "").startswith("movdqa "):
        raise ValueError("unreviewed outer codeword load")
    if body.get(outer["outer_store"]) != "movdqu %xmm0,(%rax)":
        raise ValueError("unreviewed outer completion store")


def same_word(pointer, word):
    return (f"(*(unsigned long long*)({pointer}) == 0x{word:016x}ULL && "
            f"*(unsigned long long*)(({pointer})+8) == 0x{word:016x}ULL)")


def commands(retained, outer):
    inner_symbol = retained["compute"]
    outer_symbol = outer["symbol"]
    return [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *'{outer_symbol}'",
        f"hbreak *('{inner_symbol}'+{INNER.STORE_OFFSET})", "disable 2",
        f"hbreak *('{outer_symbol}'+{outer['outer_store']})", "disable 3",
        "continue", "set $outer=(unsigned char*)$r9",
        'printf "OUTER_ENTRY %d\\n", '
        f"($outer != 0 && $outer != (unsigned char*)$rdx && "
        f"$outer != (unsigned char*)$rcx && {same_word('$outer', 0)})",
        "disable 1", "enable 2", "continue",
        'printf "OUTER_INNER %d\\n", '
        f"($rbx != $outer && {same_word('$outer', 0)} && "
        f"{same_word('(unsigned char*)$rbx', 0)})",
        "nexti",
        'printf "OUTER_INNER_DONE %d\\n", '
        f"($pc == ((unsigned long long)&'{inner_symbol}'+{INNER.RETURN_OFFSET}) && "
        f"{same_word('(unsigned char*)$rbx', 0x6969696969696969)} && "
        f"{same_word('$outer', 0)})",
        "disable 2", "enable 3", "continue",
        'printf "OUTER_STORE %d\\n", '
        f"((unsigned char*)$rax == $outer && {same_word('$outer', 0)})",
        "nexti",
        'printf "OUTER_STORE_DONE %d\\n", '
        f"($pc == ((unsigned long long)&'{outer_symbol}'+{outer['outer_store']+4}) && "
        f"{same_word('$outer', 0x6969696969696969)})",
        "disable 3", "continue",
    ]


def identity(width, path):
    if width not in RETAINED.WIDTHS or path not in RETAINED.PATHS:
        raise ValueError("unknown outer completion fixture")
    return RETAINED.identity(width, "ephemeral", path)


def validate_output(output, width, path):
    if re.findall(r"^OUTER_[^\r\n]*", output, re.M) != [
        "OUTER_ENTRY 1", "OUTER_INNER 1", "OUTER_INNER_DONE 1",
        "OUTER_STORE 1", "OUTER_STORE_DONE 1",
    ]:
        raise ValueError("outer completion checkpoints unconfirmed")
    if re.findall(r"^BRYNJA_[^\r\n]*", output, re.M) != [
        "BRYNJA_EPHEMERAL_EVIDENCE_CFG=false", f"BRYNJA_EPHEMERAL_CASE={width}:{path}",
        "BRYNJA_EPHEMERAL_STORAGE_CLEARED", "BRYNJA_EPHEMERAL_ACCEPTED",
    ]:
        raise ValueError("outer completion fixture outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 3
            or output.count("hit Breakpoint ") != 3
            or identity(width, path) not in output
            or output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or output.count("exited normally") != 1):
        raise ValueError("outer completion baseline execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    retained, outer = RETAINED.SHAPES.get(digest), SHAPES.get(digest)
    if retained is None or outer is None:
        raise ValueError("unreviewed outer completion artifact")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    inspect(dump, retained, outer)
    cases = []
    for width in RETAINED.WIDTHS:
        for path in RETAINED.PATHS:
            argv = [gdb, "-q", "-nx", "-batch"]
            for command in commands(retained, outer):
                argv += ["-ex", command]
            argv += ["--args", str(binary), "--exact", identity(width, path), "--nocapture"]
            run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
            validate_output(run.stdout + run.stderr, width, path)
            cases.append(f"aes{width * 8}/operation-local/{path}")
    if binary.read_bytes() != original or len(cases) != 9:
        raise ValueError("artifact changed or outer completion baseline incomplete")
    return {
        "schema": 1, "status": "development-outer-completion-store-observed",
        "qualification": "none", "arch": "x86_64", "toolchain": outer["toolchain"],
        "binary_sha256": digest, "inner_symbol": retained["compute"],
        "inner_store_offset": INNER.STORE_OFFSET, "outer_symbol": outer["symbol"],
        "outer_inner_call_offset": outer["inner_call"],
        "outer_store_offset": outer["outer_store"], "baseline_cases": cases,
        "limits": [
            "Public-fixture primitive-only test ELF; not a production or admitted build.",
            "Only healthy inner-to-outer completion ordering and marker values were observed.",
            "Outer check semantics, bypasses, mutations and fault-protected release remain unqualified.",
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
        print("Outer completion mapping failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Inner-to-outer completion mapped; 9 baselines; no mutations.")
        print("DEVELOPMENT_MAPPING_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
