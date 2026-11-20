#!/usr/bin/env python3
"""Observe the inner completion-codeword store in pinned test ELFs.

Read-only public-fixture mapping; outer completion and bypasses remain open.
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
STORE_OFFSET = 0x110
RETURN_OFFSET = 0x114


def inspect(dump, shape):
    RESULT.inspect(dump, shape)
    header = re.compile(r"\s*([0-9a-f]+) <(.+)>:\s*")
    instruction = re.compile(r"\s*([0-9a-f]+):\s+(.+?)\s*")
    body, selected = {}, False
    for line in dump.splitlines():
        match = header.fullmatch(line)
        if match:
            selected = match[2] == shape["compute"]
        elif selected and line.strip():
            op = instruction.fullmatch(line)
            if not op:
                raise ValueError("unparsed completion compute instruction")
            body[int(op[1], 16) - shape["compute_address"]] = re.sub(
                r"\s+", " ", op[2]).replace(", ", ",")
    expected = {
        0x0c: "mov %r9,%rbx",
        0xee: "test %al,%al",
        0xf2: "movdqa 0x10(%rsp),%xmm0",
        0xf8: "pcmpeqb (%rsp),%xmm0",
        0xfd: "pmovmskb %xmm0,%eax",
        0x101: "cmp $0xffff,%eax",
        STORE_OFFSET: "movdqu %xmm0,(%rbx)",
    }
    for offset, instruction_text in expected.items():
        if body.get(offset) != instruction_text:
            raise ValueError("unreviewed completion store or preceding checks")
    for offset in (0xf0, 0x106):
        if not body.get(offset, "").startswith("jne ") or "+0x120>" not in body[offset]:
            raise ValueError("unreviewed completion failure branch")
    if not body.get(0x108, "").startswith("movdqa "):
        raise ValueError("unreviewed completion codeword load")


def commands(shape):
    symbol = shape["compute"]
    return [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *('{symbol}'+{STORE_OFFSET})", "continue",
        'printf "COMPLETION_BEFORE %d\\n", '
        '($rbx != 0 && *(unsigned long long*)$rbx == 0 && '
        '*(unsigned long long*)($rbx+8) == 0)',
        "nexti",
        'printf "COMPLETION_AFTER %d\\n", '
        f"($pc == ((unsigned long long)&'{symbol}'+{RETURN_OFFSET}) && "
        '*(unsigned long long*)$rbx == 0x6969696969696969ULL && '
        '*(unsigned long long*)($rbx+8) == 0x6969696969696969ULL)',
        "disable 1", "continue",
    ]


def validate_output(output, width, owner, path):
    if re.findall(r"^COMPLETION_[^\r\n]*", output, re.M) != [
        "COMPLETION_BEFORE 1", "COMPLETION_AFTER 1"
    ]:
        raise ValueError("inner completion boundary unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", output, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
    ]:
        raise ValueError("completion baseline identity or outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 1
            or output.count("hit Breakpoint ") != 1
            or RETAINED.identity(width, owner, path) not in output
            or output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or output.count("exited normally") != 1):
        raise ValueError("completion baseline execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    shape = RETAINED.SHAPES.get(digest)
    if shape is None:
        raise ValueError("unreviewed completion artifact")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    inspect(dump, shape)
    cases = []
    for width in RETAINED.WIDTHS:
        for owner in RETAINED.OWNERS:
            for path in RETAINED.PATHS:
                argv = [gdb, "-q", "-nx", "-batch"]
                for command in commands(shape):
                    argv += ["-ex", command]
                argv += ["--args", str(binary), "--exact",
                         RETAINED.identity(width, owner, path), "--nocapture"]
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate_output(run.stdout + run.stderr, width, owner, path)
                cases.append(f"aes{width * 8}/{owner}/{path}")
    if binary.read_bytes() != original or len(cases) != 18:
        raise ValueError("artifact changed or completion baseline incomplete")
    return {
        "schema": 1, "status": "development-inner-completion-store-observed",
        "qualification": "none", "arch": "x86_64", "toolchain": shape["toolchain"],
        "binary_sha256": digest, "compute_symbol": shape["compute"],
        "store_offset": STORE_OFFSET, "return_offset": RETURN_OFFSET,
        "baseline_cases": cases,
        "limits": [
            "Public-fixture primitive-only test ELF; not a production or admitted build.",
            "Only healthy inner completion-codeword store ordering and value were observed.",
            "Outer completion, bypasses, mutations and fault-protected release remain unqualified.",
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
        print("Completion mapping failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Inner completion store mapped; 18 baselines; no mutations.")
        print("DEVELOPMENT_MAPPING_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
