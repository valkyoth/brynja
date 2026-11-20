#!/usr/bin/env python3
"""Observe actual secret-destination validation in pinned test ELFs.

Read-only public fixtures. This does not qualify the checks or final handoff.
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
PREFIX = "brynja_crypto::aes::fault_integrity::retained::"
GUARDED = "brynja_crypto::aes::fault_integrity::transaction::guarded_write"
VALIDATE = "brynja_crypto::aes::fault_integrity::transaction::validate"
CHECK = "brynja_crypto::aes::fault_integrity::transaction::check"
PERMIT = "brynja_crypto::aes::fault_integrity::authorization_model::permit_fresh"
SHAPES = {
    "a11c368e8eccec0e497d336ebe6a9de6381a01dfd3716887c8d69b84efa69c26": {
        "toolchain": "1.90.0", "validate_address": 0x10c520,
        "check_address": 0x10c3f0,
        "owners": {
            "cached": {"symbol": PREFIX + "Cached::secret", "address": 0x108660,
                       "guarded": 0x272, "validate": 0x2e7, "permit": 0x331},
            "ephemeral": {"symbol": PREFIX + "ephemeral::Ephemeral::secret_profile",
                          "address": 0x109b00, "guarded": 0x291,
                          "validate": 0x30f, "permit": 0x359},
        },
    },
    "bf61f409964ce7678b2a5694e63a5640d4b0a320c76d76866b25c9e95a307baf": {
        "toolchain": "1.100.0", "validate_address": 0xd10c0,
        "check_address": 0xd0fd0,
        "owners": {
            "cached": {"symbol": "<" + PREFIX + "Cached>::secret", "address": 0xc4d80,
                       "guarded": 0x1be, "validate": 0x20c, "permit": 0x256},
            "ephemeral": {"symbol": "<" + PREFIX + "ephemeral::Ephemeral>::secret_profile",
                          "address": 0xc2770, "guarded": 0x1ea,
                          "validate": 0x241, "permit": 0x28b},
        },
    },
}


def bodies(dump, names):
    header = re.compile(r"\s*([0-9a-f]+) <(.+)>:\s*")
    instruction = re.compile(r"\s*([0-9a-f]+):\s+(.+?)\s*")
    found = {}
    selected, base = None, 0
    for line in dump.splitlines():
        match = header.fullmatch(line)
        if match:
            selected = match[2] if match[2] in names else None
            if selected:
                if selected in found:
                    raise ValueError("ambiguous secret validation function")
                base = int(match[1], 16)
                found[selected] = (base, {})
        elif selected and line.strip():
            op = instruction.fullmatch(line)
            if not op:
                raise ValueError("unparsed secret validation instruction")
            found[selected][1][int(op[1], 16) - base] = re.sub(
                r"\s+", " ", op[2]).replace(", ", ",")
    if set(found) != set(names):
        raise ValueError("missing secret validation function")
    return found


def inspect(dump, shape):
    names = [VALIDATE] + [owner["symbol"] for owner in shape["owners"].values()]
    found = bodies(dump, names)
    base, body = found[VALIDATE]
    if base != shape["validate_address"]:
        raise ValueError("unreviewed actual-destination validator")
    for offset, selector in ((0x17, "xor %r8d,%r8d"),
                             (0x30, "mov $0x1,%r8d")):
        flag = offset - 3 if offset == 0x17 else offset - 6
        if body.get(flag) != selector:
            raise ValueError("unreviewed actual-destination check selector")
        if body.get(offset) != f"call {shape['check_address']:x} <{CHECK}>":
            raise ValueError("unreviewed actual-destination check call")
    if sum(op.endswith("<" + CHECK + ">") for op in body.values()) != 2:
        raise ValueError("unreviewed actual-destination check multiplicity")
    for owner in shape["owners"].values():
        base, body = found[owner["symbol"]]
        if base != owner["address"]:
            raise ValueError("unreviewed secret owner address")
        for label, target in (("guarded", GUARDED), ("validate", VALIDATE),
                              ("permit", PERMIT)):
            op = body.get(owner[label], "")
            if not op.startswith("call ") or not op.endswith("<" + target + ">"):
                raise ValueError("unreviewed secret owner call order")
        if not owner["guarded"] < owner["validate"] < owner["permit"]:
            raise ValueError("unreviewed secret release ordering")


def same_word(pointer, word):
    return (f"(*(unsigned long long*)({pointer}) == 0x{word:016x}ULL && "
            f"*(unsigned long long*)(({pointer})+8) == 0x{word:016x}ULL)")


def commands(owner, answer):
    symbol = owner["symbol"]
    offset = lambda name: f"((unsigned long long)&'{symbol}'+{owner[name]})"
    values = lambda pointer: RESULT.equal_words(pointer, answer)
    return [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *'{symbol}'",
        f"hbreak *('{symbol}'+{owner['guarded']})", "disable 2",
        f"hbreak *('{symbol}'+{owner['validate']})", "disable 3",
        f"hbreak *('{symbol}'+{owner['permit']})", "disable 4", "continue",
        "set $caller=(unsigned char*)$rcx",
        'printf "SECRET_ENTRY %d\\n", '
        f"($caller != 0 && {same_word('$caller', 0x9191919191919191)})",
        "disable 1", "enable 2", "continue",
        "set $stage=(unsigned char*)$rdi",
        'printf "SECRET_STAGE %d\\n", '
        f"($stage != $caller && {same_word('$caller', 0)} && "
        f"{values('(unsigned char*)$rsi')} && {values('(unsigned char*)$rdx')})",
        "disable 2", "nexti",
        'printf "SECRET_STAGE_DONE %d\\n", '
        f"($pc == {offset('guarded')}+5 && $al == 0)",
        "enable 3", "continue",
        'printf "SECRET_DESTINATION %d\\n", '
        f"((unsigned char*)$rdi == $caller && $rsi == 16 && "
        f"{values('$caller')} && {values('(unsigned char*)$rdx')} && "
        f"{values('(unsigned char*)$rcx')})",
        "disable 3", "nexti",
        'printf "SECRET_DESTINATION_DONE %d\\n", '
        f"($pc == {offset('validate')}+5 && $al == 0)",
        "enable 4", "continue",
        'printf "SECRET_PERMIT_NEXT %d\\n", '
        f"((unsigned char*)$rdi == $caller && $rsi == 16 && "
        f"{values('$caller')} && {same_word('(unsigned char*)$r8', 0x3c3c3c3c3c3c3c3c)})",
        "disable 4", "continue",
    ]


def validate_output(output, width, owner, path):
    if re.findall(r"^SECRET_[^\r\n]*", output, re.M) != [
        "SECRET_ENTRY 1", "SECRET_STAGE 1", "SECRET_STAGE_DONE 1",
        "SECRET_DESTINATION 1", "SECRET_DESTINATION_DONE 1",
        "SECRET_PERMIT_NEXT 1",
    ]:
        raise ValueError("actual secret-destination boundary unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", output, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
    ]:
        raise ValueError("secret-destination fixture outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 4
            or output.count("hit Breakpoint ") != 4
            or RETAINED.identity(width, owner, path) not in output
            or output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or output.count("exited normally") != 1):
        raise ValueError("secret-destination execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    shape = SHAPES.get(digest)
    if shape is None:
        raise ValueError("unreviewed secret-destination artifact")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    inspect(dump, shape)
    cases = []
    for width in RETAINED.WIDTHS:
        for owner in RETAINED.OWNERS:
            for path in ("encrypt", "decrypt"):
                answer = RESULT.PLAIN if path == "decrypt" else RESULT.CIPHERS[width]
                argv = [gdb, "-q", "-nx", "-batch"]
                for command in commands(shape["owners"][owner], answer):
                    argv += ["-ex", command]
                argv += ["--args", str(binary), "--exact",
                         RETAINED.identity(width, owner, path), "--nocapture"]
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate_output(run.stdout + run.stderr, width, owner, path)
                cases.append(f"aes{width * 8}/{owner}/{path}")
    if binary.read_bytes() != original or len(cases) != 12:
        raise ValueError("artifact changed or secret-destination baseline incomplete")
    return {
        "schema": 1, "status": "development-actual-secret-destination-observed",
        "qualification": "none", "arch": "x86_64", "toolchain": shape["toolchain"],
        "binary_sha256": digest, "validate_symbol": VALIDATE,
        "validate_check_offsets": [23, 48],
        "owners": shape["owners"], "baseline_cases": cases,
        "limits": [
            "Public-fixture primitive-only test ELF; not a production or admitted build.",
            "Secret staging differs from caller destination; actual bytes are checked before permit.",
            "The two validator calls share one check implementation and do not establish fault independence.",
            "No mutation, bypass, DC1 pairing, final handoff or physical fault was tested.",
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
        print("Secret-destination mapping failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Actual secret-destination check mapped; 12 baselines; no mutations.")
        print("DEVELOPMENT_MAPPING_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
