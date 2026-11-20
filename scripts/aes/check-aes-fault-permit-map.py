#!/usr/bin/env python3
"""Observe the deny-first final-permit boundary in pinned test ELFs.

Read-only public-vector breakpoints; this does not qualify C1 or L1.
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
RESULT = INNER.RESULT
SYMBOL = "brynja_crypto::aes::fault_integrity::authorization_model::permit_fresh"
SHAPES = {
    "a11c368e8eccec0e497d336ebe6a9de6381a01dfd3716887c8d69b84efa69c26": {
        "toolchain": "1.90.0", "address": 0x1045c0, "deny_load": 0x10,
        "deny_store": 0x15, "observe_call": 0x31, "guarded_call": 0x92,
        "return_offset": 0x18d,
    },
    "bf61f409964ce7678b2a5694e63a5640d4b0a320c76d76866b25c9e95a307baf": {
        "toolchain": "1.100.0", "address": 0xd2580, "deny_load": 0x10,
        "deny_store": 0x14, "observe_call": 0x2f, "guarded_call": 0x8f,
        "return_offset": 0xf0,
    },
}


def inspect(dump, shape):
    header = re.compile(r"\s*([0-9a-f]+) <(.+)>:\s*")
    instruction = re.compile(r"\s*([0-9a-f]+):\s+(.+?)\s*")
    body, selected, found = {}, False, 0
    for line in dump.splitlines():
        match = header.fullmatch(line)
        if match:
            selected = match[2] == SYMBOL
            if selected:
                found += 1
                if int(match[1], 16) != shape["address"]:
                    raise ValueError("unreviewed permit address")
        elif selected and line.strip():
            op = instruction.fullmatch(line)
            if not op:
                raise ValueError("unparsed permit instruction")
            body[int(op[1], 16) - shape["address"]] = re.sub(
                r"\s+", " ", op[2]).replace(", ", ",")
    if found != 1:
        raise ValueError("missing or ambiguous permit function")
    load, store = body.get(shape["deny_load"], ""), body.get(shape["deny_store"], "")
    if load not in ("movdqu (%r9),%xmm0", "movups (%r9),%xmm0"):
        raise ValueError("unreviewed denied-state load")
    if store not in ("movdqu %xmm0,(%r8)", "movups %xmm0,(%r8)"):
        raise ValueError("unreviewed denied-state store")
    observe = body.get(shape["observe_call"], "")
    guarded = body.get(shape["guarded_call"], "")
    if not (observe.startswith("call ") and "Candidate" in observe
            and "::observe" in observe):
        raise ValueError("unreviewed fresh receipt call")
    if not (guarded.startswith("call ") and "guarded_copy::tentative_copy_16" in guarded):
        raise ValueError("unreviewed guarded state rewrite")
    if body.get(shape["return_offset"]) != "ret":
        raise ValueError("unreviewed permit return")
    if sum(op == "ret" for op in body.values()) != 1:
        raise ValueError("unreviewed permit return multiplicity")


def same_word(pointer, word):
    return (f"(*(unsigned long long*)({pointer}) == 0x{word:016x}ULL && "
            f"*(unsigned long long*)(({pointer})+8) == 0x{word:016x}ULL)")


def commands(shape, expected):
    return [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *'{SYMBOL}'",
        f"hbreak *('{SYMBOL}'+{shape['guarded_call']})", "disable 2",
        f"hbreak *('{SYMBOL}'+{shape['return_offset']})", "disable 3",
        "continue", "set $state=(unsigned char*)$r8",
        "set $destination=(unsigned char*)$rdi",
        'printf "PERMIT_ENTRY %d\\n", '
        f"($rsi == 16 && $state != $destination && "
        f"{same_word('$state', 0x3c3c3c3c3c3c3c3c)} && "
        f"{same_word('(unsigned char*)$r9', 0xc3c3c3c3c3c3c3c3)} && "
        f"{RESULT.equal_words('$destination', expected)})",
        "disable 1", "enable 2", "continue",
        'printf "PERMIT_DENIED %d\\n", '
        f"((unsigned char*)$rdi == $state && "
        f"{same_word('$state', 0xc3c3c3c3c3c3c3c3)} && "
        f"{RESULT.equal_words('$destination', expected)})",
        "disable 2", "enable 3", "continue",
        'printf "PERMIT_RETURN %d\\n", '
        f"($al == 0 && {same_word('$state', 0x3c3c3c3c3c3c3c3c)} && "
        f"{RESULT.equal_words('$destination', expected)})",
        "disable 3", "continue",
    ]


def validate_output(output, width, owner, path):
    if re.findall(r"^PERMIT_[^\r\n]*", output, re.M) != [
        "PERMIT_ENTRY 1", "PERMIT_DENIED 1", "PERMIT_RETURN 1"
    ]:
        raise ValueError("permit boundary or public answer unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", output, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
    ]:
        raise ValueError("permit baseline identity or outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 3
            or output.count("hit Breakpoint ") != 3
            or RETAINED.identity(width, owner, path) not in output
            or output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or output.count("exited normally") != 1):
        raise ValueError("permit baseline execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    shape = SHAPES.get(digest)
    if shape is None:
        raise ValueError("unreviewed permit artifact")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    inspect(dump, shape)
    cases = []
    for width in RETAINED.WIDTHS:
        for owner in RETAINED.OWNERS:
            for path in RETAINED.PATHS:
                expected = RESULT.PLAIN if path == "decrypt" else RESULT.CIPHERS[width]
                argv = [gdb, "-q", "-nx", "-batch"]
                for command in commands(shape, expected):
                    argv += ["-ex", command]
                argv += ["--args", str(binary), "--exact",
                         RETAINED.identity(width, owner, path), "--nocapture"]
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate_output(run.stdout + run.stderr, width, owner, path)
                cases.append(f"aes{width * 8}/{owner}/{path}")
    if binary.read_bytes() != original or len(cases) != 18:
        raise ValueError("artifact changed or permit baseline incomplete")
    return {
        "schema": 1, "status": "development-final-permit-boundaries-observed",
        "qualification": "none", "arch": "x86_64", "toolchain": shape["toolchain"],
        "binary_sha256": digest, "permit_symbol": SYMBOL,
        "deny_store_offset": shape["deny_store"],
        "receipt_call_offset": shape["observe_call"],
        "guarded_call_offset": shape["guarded_call"],
        "return_offset": shape["return_offset"], "baseline_cases": cases,
        "limits": [
            "Public-fixture primitive-only test ELF; not a production or admitted build.",
            "Only healthy deny-first entry, guarded-copy call and return values were observed.",
            "Receipt internals, bypasses, failures and fault-protected release remain unqualified.",
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
        print("Permit mapping failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Deny-first permit boundary mapped; 18 baselines; no mutations.")
        print("DEVELOPMENT_MAPPING_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
