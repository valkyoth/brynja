#!/usr/bin/env python3
"""Observe retained pre/post validation calls in pinned test ELFs.

Read-only public-fixture breakpoints. This maps call order only: it neither
mutates retained storage nor qualifies the internal key/schedule comparisons.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


BASE = "brynja_crypto::aes::fault_integrity::retained::Retained"
OWNERS = ("cached", "ephemeral")
PATHS = ("public", "encrypt", "decrypt")
WIDTHS = (16, 24, 32)
MARKERS = ("VALIDATE_PRE", "VALIDATE_PRE_DONE", "VALIDATE_POST", "VALIDATE_POST_DONE")
SHAPES = {
    "a11c368e8eccec0e497d336ebe6a9de6381a01dfd3716887c8d69b84efa69c26": {
        "toolchain": "1.90.0", "compute": BASE + "::compute", "validate": BASE + "::validate",
        "compute_address": 0x107fc0, "validate_address": 0x1076f0,
        "call_offsets": (0x58, 0xe9),
    },
    "bf61f409964ce7678b2a5694e63a5640d4b0a320c76d76866b25c9e95a307baf": {
        "toolchain": "1.100.0", "compute": "<" + BASE + ">::compute",
        "validate": "<" + BASE + ">::validate",
        "compute_address": 0xc3ee0, "validate_address": 0xc4050,
        "call_offsets": (0x58, 0xe9),
    },
}


def inspect(dump, shape):
    header = re.compile(r"\s*([0-9a-f]+) <(.+)>:\s*")
    instruction = re.compile(r"\s*([0-9a-f]+):\s+(.+?)\s*")
    body, selected, found = [], False, 0
    for line in dump.splitlines():
        match = header.fullmatch(line)
        if match:
            selected = match[2] == shape["compute"]
            if selected:
                found += 1
                if int(match[1], 16) != shape["compute_address"]:
                    raise ValueError("unreviewed retained compute address")
        elif selected and line.strip():
            op = instruction.fullmatch(line)
            if not op:
                raise ValueError("unparsed retained compute instruction")
            body.append((int(op[1], 16), re.sub(r"\s+", " ", op[2]).replace(", ", ",")))
    if found != 1:
        raise ValueError("missing or ambiguous retained compute function")
    calls = [(index, address) for index, (address, op) in enumerate(body)
             if shape["validate"] in op]
    if len(calls) != 2 or tuple(address - shape["compute_address"]
                                for _, address in calls) != shape["call_offsets"]:
        raise ValueError("unreviewed retained validation call count or offsets")
    for index, address in calls:
        expected = [
            "mov %r14,%rdi",
            f'call {shape["validate_address"]:x} <{shape["validate"]}>',
            "test %al,%al",
            f'jne {shape["compute_address"] + 0x120:x} <{shape["compute"]}+0x120>',
        ]
        if [op for _, op in body[index - 1:index + 3]] != expected:
            raise ValueError("unreviewed retained validation branch shape")
        if body[index + 1][0] != address + 5:
            raise ValueError("unreviewed retained validation return boundary")
    between = [op for _, op in body[calls[0][0] + 1:calls[1][0]]]
    if sum("schedule::Schedule" in op and "::transform" in op
           and op.startswith("call ") for op in between) != 1:
        raise ValueError("retained transform not between validation calls")


def identity(width, owner, path):
    if width not in WIDTHS or owner not in OWNERS or path not in PATHS:
        raise ValueError("unknown retained baseline fixture")
    return ("aes::fault_integrity::retained::probe_tests::"
            f"native_{owner}_{width * 8}_{path}")


def commands(shape):
    symbol = shape["compute"]
    pre, post = shape["call_offsets"]
    address = lambda offset: f"((unsigned long long)&'{symbol}' + {offset})"
    return [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *('{symbol}'+{pre})", f"hbreak *('{symbol}'+{post})",
        "disable 2", "continue", "set $retained=(unsigned char*)$rdi",
        'printf "VALIDATE_PRE %d\\n", ($retained != 0)',
        "disable 1", "nexti",
        f'printf "VALIDATE_PRE_DONE %d\\n", ($pc == {address(pre + 5)} && $al == 0)',
        "enable 2", "continue",
        'printf "VALIDATE_POST %d\\n", ((unsigned char*)$rdi == $retained)',
        "disable 2", "nexti",
        f'printf "VALIDATE_POST_DONE %d\\n", ($pc == {address(post + 5)} && $al == 0)',
        "continue",
    ]


def validate(output, width, owner, path):
    test = identity(width, owner, path)
    if re.findall(r"^VALIDATE_[^\r\n]*", output, re.M) != [
        marker + " 1" for marker in MARKERS
    ]:
        raise ValueError("retained validation checkpoints unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", output, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
    ]:
        raise ValueError("retained baseline identity or outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 2
            or output.count("hit Breakpoint ") != 2 or test not in output
            or output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or output.count("exited normally") != 1):
        raise ValueError("retained baseline execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    shape = SHAPES.get(digest)
    if shape is None:
        raise ValueError("unreviewed retained artifact")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    inspect(dump, shape)
    cases = []
    for width in WIDTHS:
        for owner in OWNERS:
            for path in PATHS:
                test = identity(width, owner, path)
                argv = [gdb, "-q", "-nx", "-batch"]
                for command in commands(shape):
                    argv += ["-ex", command]
                argv += ["--args", str(binary), "--exact", test, "--nocapture"]
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate(run.stdout + run.stderr, width, owner, path)
                cases.append(f"aes{width * 8}/{owner}/{path}")
    if binary.read_bytes() != original or len(cases) != 18:
        raise ValueError("artifact changed or retained baseline incomplete")
    return {
        "schema": 1, "status": "development-retained-validation-calls-observed",
        "qualification": "none", "arch": "x86_64", "toolchain": shape["toolchain"],
        "binary_sha256": digest, "compute_symbol": shape["compute"],
        "validate_symbol": shape["validate"], "call_offsets": list(shape["call_offsets"]),
        "baseline_cases": cases,
        "limits": [
            "Public-fixture primitive-only test ELF; not a production or admitted build.",
            "Only pre/post validation call order and successful baseline returns were observed.",
            "No retained-key mutation, per-byte comparison, bypass pairing, timing or physical fault was tested.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--json", action="store_true", help="emit bounded metadata, not debugger output")
    args = parser.parse_args()
    try:
        report = observe(args.binary, args.objdump, args.gdb)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print("Retained validation mapping failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Retained pre/post validation calls mapped; 18 baselines; no mutations.")
        print("DEVELOPMENT_MAPPING_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
