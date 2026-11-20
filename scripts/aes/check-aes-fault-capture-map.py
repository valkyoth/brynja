#!/usr/bin/env python3
"""Observe two capture calls in a trusted x86-64 test ELF; NOT qualification.

Hardware debugger stops only, using public FIPS fixtures. No memory/register
mutation, code patching, or secret dumps. Unknown code shapes fail closed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

from aes_fault_capture_map import inspect

SPEC = importlib.util.spec_from_file_location(
    "retained_probe", Path(__file__).with_name("check-aes-fault-retained.py"))
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)
SCOPES = ("key", "input")
MARKERS = ("MAP_ENTRY", "MAP_FIRST_CALL", "MAP_FIRST_DONE", "MAP_SECOND_CALL", "MAP_SECOND_DONE", "MAP_RETURN")


def at(function, event):
    return f"('{function['symbol']}'+{function['events'][event]})"


def address(function, event):
    # Cast the function ADDRESS, not the function value plus an offset. GDB
    # accepts the latter for breakpoints but cannot use it in integer equality.
    return f"((unsigned long long)&'{function['symbol']}' + {function['events'][event]})"


def commands(mapping, width, owner, path, scope):
    test = R.C.identity(width, path, "baseline", owner)
    if scope not in SCOPES:
        raise ValueError("unknown capture scope")
    capture, wrapper, copy = (mapping[name] for name in ("capture", "wrapper", "copy"))
    source = bytes(range(width)) if scope == "key" else bytes.fromhex(
        R.C.ANSWERS[width] if path == "decrypt" else R.C.PLAIN)
    length = len(source)
    old_first = bytes([0x91 if scope == "key" else 0]) * length
    old_second = bytes([0x92 if scope == "key" else 0]) * length
    source_ok = R.bytes_at("$source", source)
    first_ok, second_ok = R.bytes_at("$first", source), R.bytes_at("$second", source)
    result = ["set debuginfod enabled off", "set pagination off", "set print thread-events off",
              "set disable-randomization off", "starti", "set language c",
              f"hbreak *{at(capture, 'entry')}", f"hbreak *{at(wrapper, 'entry')}",
              f"hbreak *{at(copy, 'return')}", f"hbreak *{at(capture, 'return')}",
              "disable 2", "disable 3", "disable 4"]
    if scope == "input":
        result.append("ignore 1 1")
    result += ["continue", "set $source=(unsigned char*)$rdi",
               "set $first=(unsigned char*)$rdx", "set $second=(unsigned char*)$r8"]
    # Check full half-open range separation, not merely unequal starts.
    distinct = [f"({a}+{length} <= {b} || {b}+{length} <= {a})"
                for a, b in (("$source", "$first"), ("$source", "$second"), ("$first", "$second"))]
    entry = [source_ok, R.bytes_at("$first", old_first), R.bytes_at("$second", old_second),
             f"$rsi == {length}", f"$rcx == {length}", f"$r9 == {length}"] + distinct
    result += ['printf "MAP_ENTRY %d\\n", (' + " && ".join(entry) + ")", "disable 1"]
    for which in ("first", "second"):
        destination = "$" + which
        after = "after_" + which + "_call"
        result += ["enable 2", "continue"]
        call = [f"(unsigned char*)$rdi == {destination}", f"$rsi == {length}",
                "(unsigned char*)$rdx == $source", f"$rcx == {length}", source_ok,
                f"*(unsigned long long*)$rsp == {address(capture, after)}"]
        result += [f'printf "MAP_{which.upper()}_CALL %d\\n", (' + " && ".join(call) + ")",
                   "disable 2", "enable 3", "continue"]
        done = [f"(unsigned char*)$rdi == {destination}", "(unsigned char*)$rsi == $source",
                f"*(unsigned long long*)$rsp == {address(wrapper, 'after_copy_call')}",
                source_ok, first_ok,
                R.bytes_at("$second", old_second) if which == "first" else second_ok]
        result += [f'printf "MAP_{which.upper()}_DONE %d\\n", (' + " && ".join(done) + ")", "disable 3"]
    result += ["enable 4", "continue",
               f'printf "MAP_RETURN %d\\n", ($al == 0 && {source_ok} && {first_ok} && {second_ok})',
               "disable 4", "continue"]
    return result, test


def validate(text, width, owner, path, scope):
    test = R.C.identity(width, path, "baseline", owner)
    if scope not in SCOPES:
        raise ValueError("unknown capture scope")
    if re.findall(r"^MAP_[^\r\n]*", text, re.M) != [marker + " 1" for marker in MARKERS]:
        raise ValueError("capture mapping checkpoints unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", text, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
    ]:
        raise ValueError("capture fixture identity or baseline outcome unconfirmed")
    if (text.count("Hardware assisted breakpoint ") != 4 or text.count("hit Breakpoint ") != 6
            or test not in text or text.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or text.count("exited normally") != 1):
        raise ValueError("capture mapping execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    mapping = inspect(dump)
    cases = []
    for width in R.C.ANSWERS:
        for owner in R.C.OWNERS:
            for path in R.C.PATHS:
                for scope in SCOPES:
                    experiment, test = commands(mapping, width, owner, path, scope)
                    argv = [gdb, "-q", "-nx", "-batch"]
                    for command in experiment:
                        argv += ["-ex", command]
                    argv += ["--args", str(binary), "--exact", test, "--nocapture"]
                    run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                    validate(run.stdout + run.stderr, width, owner, path, scope)
                    cases.append(f"aes{width * 8}/{owner}/{path}/{scope}")
    if binary.read_bytes() != original or len(cases) != 36:
        raise ValueError("artifact changed or mapping observation incomplete")
    return {"schema": 1, "status": "development-capture-map-observed", "qualification": "none",
            "binary_sha256": hashlib.sha256(original).hexdigest(), "arch": "x86_64",
            "functions": mapping, "baseline_cases": cases,
            "limits": ["Public-fixture test ELF, not a production artifact or admitted build.",
                       "No mutations, C1/DC1 combinations, timing or fault detection tested.",
                       "Fixed lengths 16/24/32 use word copies; byte-tail loop is static mapping only.",
                       "Return boundaries are not within-store instruction fault sites."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--json", action="store_true", help="emit only bounded mapping metadata, not debugger output")
    args = parser.parse_args()
    try:
        report = observe(args.binary, args.objdump, args.gdb)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Never echo subprocess commands, stdout/stderr, register or fixture data.
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print("Capture mapping failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Capture call-chain mapped; 36 baseline cases observed; no data mutations.")
        print("DEVELOPMENT_MAPPING_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
