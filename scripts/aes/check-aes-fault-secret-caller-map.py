#!/usr/bin/env python3
"""Observe secret-result return into the pinned public-fixture caller.

Read-only fixture data. This does not test faults or qualify the final handoff.
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
    "secret_result_map", Path(__file__).with_name("check-aes-fault-secret-result-map.py"))
RESULT_MAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESULT_MAP)
DEST = RESULT_MAP.DEST
RESULT = RESULT_MAP.RESULT
RETAINED = RESULT_MAP.RETAINED
CALLER_PREFIX = "brynja_crypto::aes::fault_integrity::retained::probe_tests::run_"
SHAPES = {
    "a11c368e8eccec0e497d336ebe6a9de6381a01dfd3716887c8d69b84efa69c26": {
        "toolchain": "1.90.0", "callers": {
            "cached": {"symbol": CALLER_PREFIX + "cached", "address": 0x113c60,
                       "call": 0x45a, "status": 0x46b,
                       "status_instruction": "cmpl $0x1,0x40(%rsp)"},
            "ephemeral": {"symbol": CALLER_PREFIX + "ephemeral", "address": 0x1144e0,
                          "call": 0x374, "status": 0x379,
                          "status_instruction": "cmpb $0x0,0x10(%rsp)"},
        },
    },
    "bf61f409964ce7678b2a5694e63a5640d4b0a320c76d76866b25c9e95a307baf": {
        "toolchain": "1.100.0", "callers": {
            "cached": {"symbol": CALLER_PREFIX + "cached", "address": 0xdf560,
                       "call": 0x3d9, "status": 0x3e5,
                       "status_instruction": "cmpl $0x1,0x358(%rsp)"},
            "ephemeral": {"symbol": CALLER_PREFIX + "ephemeral", "address": 0xdfce0,
                          "call": 0x340, "status": 0x345,
                          "status_instruction": "cmpb $0x0,0x28(%rsp)"},
        },
    },
}


def inspect(dump, shape, owner_shape):
    found = DEST.bodies(dump, [caller["symbol"] for caller in shape["callers"].values()])
    for name, caller in shape["callers"].items():
        base, body = found[caller["symbol"]]
        if base != caller["address"]:
            raise ValueError("unreviewed fixture caller address")
        target = owner_shape["owners"][name]
        if body.get(caller["call"]) != f"call {target['address']:x} <{target['symbol']}>":
            raise ValueError("unreviewed fixture secret call")
        if body.get(caller["status"]) != caller["status_instruction"]:
            raise ValueError("unreviewed fixture status test")
        if not caller["call"] < caller["status"]:
            raise ValueError("unreviewed fixture call/return ordering")


def commands(caller, answer):
    symbol = caller["symbol"]
    call = f"((unsigned long long)&'{symbol}'+{caller['call']})"
    values = lambda pointer: RESULT.equal_words(pointer, answer)
    return [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *('{symbol}'+{caller['call']})", "continue",
        "set $caller=(unsigned char*)$rcx", "set $result=(unsigned char*)$rdi",
        'printf "SECRET_CALLER_ENTRY %d\\n", '
        f"($caller != 0 && $result != 0 && {DEST.same_word('$caller', 0x9191919191919191)})",
        "disable 1", "nexti",
        'printf "SECRET_CALLER_RETURN %d\\n", '
        f"($pc == {call}+5 && {values('$caller')} && "
        "*(unsigned char*)$result == 0 && "
        "*(unsigned char**)($result+8) == $caller && "
        "*(unsigned long long*)($result+16) == 16)",
        "continue",
    ]


def validate_output(output, width, owner, path):
    if re.findall(r"^SECRET_CALLER_[^\r\n]*", output, re.M) != [
        "SECRET_CALLER_ENTRY 1", "SECRET_CALLER_RETURN 1",
    ]:
        raise ValueError("secret fixture-caller return unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", output, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
    ]:
        raise ValueError("secret fixture-caller outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 1
            or output.count("hit Breakpoint ") != 1
            or RETAINED.identity(width, owner, path) not in output
            or output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or output.count("exited normally") != 1):
        raise ValueError("secret fixture-caller execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    shape, owner_shape = SHAPES.get(digest), DEST.SHAPES.get(digest)
    if shape is None or owner_shape is None:
        raise ValueError("unreviewed fixture-caller artifact")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    inspect(dump, shape, owner_shape)
    cases = []
    for width in RETAINED.WIDTHS:
        for owner in RETAINED.OWNERS:
            for path in ("encrypt", "decrypt"):
                answer = RESULT.PLAIN if path == "decrypt" else RESULT.CIPHERS[width]
                argv = [gdb, "-q", "-nx", "-batch"]
                for command in commands(shape["callers"][owner], answer):
                    argv += ["-ex", command]
                argv += ["--args", str(binary), "--exact",
                         RETAINED.identity(width, owner, path), "--nocapture"]
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate_output(run.stdout + run.stderr, width, owner, path)
                cases.append(f"aes{width * 8}/{owner}/{path}")
    if binary.read_bytes() != original or len(cases) != 12:
        raise ValueError("artifact changed or fixture-caller baseline incomplete")
    return {
        "schema": 1, "status": "development-secret-fixture-caller-return-observed",
        "qualification": "none", "arch": "x86_64", "toolchain": shape["toolchain"],
        "binary_sha256": digest, "callers": shape["callers"], "baseline_cases": cases,
        "limits": [
            "Public-fixture primitive-only test ELF; not a production or admitted build.",
            "Healthy return into this exact fixture caller, not a general API proof.",
            "No post-validation corruption, bypass, failed branch, DC1 pairing or physical fault was tested.",
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
        print("Secret fixture-caller mapping failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Secret fixture-caller return mapped; 12 baselines; no mutations.")
        print("DEVELOPMENT_MAPPING_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
