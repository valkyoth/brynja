#!/usr/bin/env python3
"""Observe secret-result construction after lifecycle completion in pinned ELFs.

Read-only public fixtures. This is neither a fault test nor a final-handoff proof.
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
    "secret_destination_map", Path(__file__).with_name(
        "check-aes-fault-secret-destination-map.py"))
DEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEST)
RESULT = DEST.RESULT
RETAINED = DEST.RETAINED
COMPLETE = "brynja_crypto::aes::fault_integrity::transaction::Operation::complete"
SHAPES = {
    "a11c368e8eccec0e497d336ebe6a9de6381a01dfd3716887c8d69b84efa69c26": {
        "toolchain": "1.90.0", "complete_address": 0x10bf80,
        "complete_symbol": COMPLETE,
        "owners": {
            "cached": {"complete": 0x342, "pointer_store": 0x38c,
                       "length_store": 0x390, "result_register": "rbx"},
            "ephemeral": {"complete": 0x36b, "pointer_store": 0x3a0,
                          "length_store": 0x3a4, "result_register": "rcx"},
        },
    },
    "bf61f409964ce7678b2a5694e63a5640d4b0a320c76d76866b25c9e95a307baf": {
        "toolchain": "1.100.0", "complete_address": 0xc37c0,
        "complete_symbol": "<" + COMPLETE.rsplit("::", 1)[0] + ">::complete",
        "owners": {
            "cached": {"complete": 0x268, "pointer_store": 0x2af,
                       "length_store": 0x2b3, "result_register": "rbx"},
            "ephemeral": {"complete": 0x29d, "pointer_store": 0x2d2,
                          "length_store": 0x2d6, "result_register": "rcx"},
        },
    },
}


def inspect(dump, shape, destination):
    names = [owner["symbol"] for owner in destination["owners"].values()]
    found = DEST.bodies(dump, names)
    for name, owner in destination["owners"].items():
        local = shape["owners"][name]
        base, body = found[owner["symbol"]]
        if base != owner["address"]:
            raise ValueError("unreviewed secret owner address")
        if body.get(local["complete"]) != (
                f"call {shape['complete_address']:x} <{shape['complete_symbol']}>"):
            raise ValueError("unreviewed lifecycle completion call")
        register = local["result_register"]
        if body.get(local["pointer_store"]) != f"mov %rax,0x8(%{register})":
            raise ValueError("unreviewed secret result pointer store")
        if body.get(local["length_store"]) != f"movq $0x10,0x10(%{register})":
            raise ValueError("unreviewed secret result length store")
        if not (owner["permit"] < local["complete"] <
                local["pointer_store"] < local["length_store"]):
            raise ValueError("unreviewed secret result ordering")
        if sum(op.endswith("<" + shape["complete_symbol"] + ">")
               for op in body.values()) != 1:
            raise ValueError("unreviewed lifecycle completion multiplicity")


def commands(owner, local, answer):
    symbol = owner["symbol"]
    reg = "$" + local["result_register"]
    offset = lambda name: f"((unsigned long long)&'{symbol}'+{local[name]})"
    values = lambda pointer: RESULT.equal_words(pointer, answer)
    return [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *'{symbol}'",
        f"hbreak *('{symbol}'+{local['complete']})", "disable 2",
        f"hbreak *('{symbol}'+{local['pointer_store']})", "disable 3",
        "continue", "set $caller=(unsigned char*)$rcx",
        "set $result=(unsigned char*)$rdi",
        'printf "SECRET_RESULT_ENTRY %d\\n", ($caller != 0 && $result != 0 && '
        f"{DEST.same_word('$caller', 0x9191919191919191)})",
        "disable 1", "enable 2", "continue",
        'printf "SECRET_RESULT_COMPLETE %d\\n", '
        f"({values('$caller')} && $result != $caller)",
        "disable 2", "nexti",
        'printf "SECRET_RESULT_COMPLETED %d\\n", '
        f"($pc == {offset('complete')}+5 && $al == 0)",
        "enable 3", "continue",
        'printf "SECRET_RESULT_POINTER %d\\n", '
        f"($rax == $caller && {reg} == $result && {values('$caller')})",
        "disable 3", "nexti",
        'printf "SECRET_RESULT_POINTER_STORED %d\\n", '
        "(*(unsigned char**)($result+8) == $caller)",
        'printf "SECRET_RESULT_LENGTH %d\\n", '
        f"($pc == {offset('length_store')} && {reg} == $result && "
        "*(unsigned char**)($result+8) == $caller)",
        "nexti",
        'printf "SECRET_RESULT_LENGTH_STORED %d\\n", '
        "(*(unsigned long long*)($result+16) == 16)",
        "continue",
    ]


def validate_output(output, width, owner, path):
    markers = re.findall(r"^SECRET_RESULT_[^\r\n]*", output, re.M)
    if markers != [
        "SECRET_RESULT_ENTRY 1", "SECRET_RESULT_COMPLETE 1",
        "SECRET_RESULT_COMPLETED 1", "SECRET_RESULT_POINTER 1",
        "SECRET_RESULT_POINTER_STORED 1", "SECRET_RESULT_LENGTH 1",
        "SECRET_RESULT_LENGTH_STORED 1",
    ]:
        raise ValueError("secret-result construction unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", output, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
    ]:
        raise ValueError("secret-result fixture outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 3
            or output.count("hit Breakpoint ") != 3
            or RETAINED.identity(width, owner, path) not in output
            or output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or output.count("exited normally") != 1):
        raise ValueError("secret-result fixture execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    shape, destination = SHAPES.get(digest), DEST.SHAPES.get(digest)
    if shape is None or destination is None:
        raise ValueError("unreviewed secret-result artifact")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    inspect(dump, shape, destination)
    cases = []
    for width in RETAINED.WIDTHS:
        for owner in RETAINED.OWNERS:
            for path in ("encrypt", "decrypt"):
                answer = RESULT.PLAIN if path == "decrypt" else RESULT.CIPHERS[width]
                argv = [gdb, "-q", "-nx", "-batch"]
                for command in commands(destination["owners"][owner], shape["owners"][owner],
                                        answer):
                    argv += ["-ex", command]
                argv += ["--args", str(binary), "--exact",
                         RETAINED.identity(width, owner, path), "--nocapture"]
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate_output(run.stdout + run.stderr, width, owner, path)
                cases.append(f"aes{width * 8}/{owner}/{path}")
    if binary.read_bytes() != original or len(cases) != 12:
        raise ValueError("artifact changed or secret-result baseline incomplete")
    return {
        "schema": 1, "status": "development-secret-result-construction-observed",
        "qualification": "none", "arch": "x86_64", "toolchain": shape["toolchain"],
        "binary_sha256": digest, "complete_symbol": shape["complete_symbol"],
        "complete_address": shape["complete_address"],
        "owners": shape["owners"], "baseline_cases": cases,
        "limits": [
            "Public-fixture primitive-only test ELF; not a production or admitted build.",
            "Healthy completion precedes result descriptor stores in these exact artifacts.",
            "Result construction is not a proof of final caller handoff or fault resistance.",
            "No mutation, bypass, DC1 pairing, failed branch or physical fault was tested.",
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
        print("Secret-result mapping failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Secret-result construction mapped; 12 baselines; no mutations.")
        print("DEVELOPMENT_MAPPING_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
