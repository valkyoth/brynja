#!/usr/bin/env python3
"""Finite native key-import store observations; trusted public-fixture ELFs only.

No source fault hooks, code patching, retries, key dumps or qualification claim.
The selected register mutation changes one stored key byte, not caller memory.
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
    "copy_store", Path(__file__).with_name("check-aes-fault-copy-store.py"))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
M, R = C.M, C.R
WIDTHS = (16, 24, 32)
OWNERS = ("cached", "ephemeral")
CASES = ("baseline", "data")


def identity(width, owner, replica, byte, case):
    if (type(width) is not int or width not in WIDTHS or owner not in OWNERS
            or replica not in C.REPLICAS or type(byte) is not int or not 0 <= byte < width
            or case not in CASES or (case == "baseline" and byte != 0)):
        raise ValueError("invalid import-store selection")
    return f"aes::fault_integrity::retained::probe_tests::import_tests::native_import_{owner}_{width * 8}"


def commands(mapping, width, owner, replica, byte, case):
    test = identity(width, owner, replica, byte, case)
    source = bytes(range(width))
    changed = bytearray(source)
    if case == "data":
        changed[byte] ^= 1
    changed = bytes(changed)
    offset = byte // 8 * 8
    word = int.from_bytes(source[offset:offset+8], "little")
    mask = 1 << (byte % 8 * 8)
    proposed = word ^ mask if case == "data" else word
    target, other = "$" + replica, "$second" if replica == "first" else "$first"
    sentinel = 0x91 if replica == "first" else 0x92
    before = source[:offset] + bytes([sentinel]) * (width - offset)
    after = changed[:offset+8] + bytes([sentinel]) * (width - offset - 8)
    other_before = bytes([0x92]) * width if replica == "first" else source
    capture, copy = mapping["capture"], mapping["copy"]
    guards = "(*($first-1) == 0x91 && *($second-1) == 0x92 && " + f"*($first+{width}) == 0x91 && *($second+{width}) == 0x92)"
    cmds = ["set debuginfod enabled off", "set pagination off", "set print thread-events off",
            "set disable-randomization off", "starti", "set language c",
            f"hbreak *{M.at(capture, 'entry')}", f"hbreak *{M.at(copy, 'word_store')}",
            f"hbreak *{M.at(capture, 'return')}", "disable 2", "disable 3", "continue",
            "set $source=(unsigned char*)$rdi", "set $first=(unsigned char*)$rdx", "set $second=(unsigned char*)$r8"]
    pointers = ("$source", "$first", "$second")
    checks = [f"$rsi == {width}", f"$rcx == {width}", f"$r9 == {width}",
              R.bytes_at("$source", source), R.bytes_at("$first", bytes([0x91])*width),
              R.bytes_at("$second", bytes([0x92])*width), guards]
    checks += [f"({a}+{width} <= {b} || {b}+{width} <= {a})" for i,a in enumerate(pointers) for b in pointers[i+1:]]
    cmds += ['printf "IMPORT_ENTRY %d\\n", (' + " && ".join(checks) + ")", "disable 1", "enable 2"]
    skip = (width // 8 if replica == "second" else 0) + byte // 8
    if skip:
        cmds.append(f"ignore 2 {skip}")
    cmds += ["continue"]
    checks = [f"(unsigned long long)$pc == {M.address(copy, 'word_store')}",
              f"(unsigned char*)$rdi == {target}", "(unsigned char*)$rsi == $source",
              f"$rcx == {offset}", f"$rdx == {width-offset}", f"$rax == {word}ULL",
              R.bytes_at("$source", source), R.bytes_at(target, before), R.bytes_at(other, other_before), guards]
    cmds += ['printf "IMPORT_BEFORE %d\\n", (' + " && ".join(checks) + ")"]
    if case == "data":
        cmds.append(f"set $rax = $rax ^ {mask}ULL")
    cmds += [f'printf "IMPORT_VALUE %d\\n", ($rax == {proposed}ULL && {R.bytes_at("$source", source)} && {R.bytes_at(target, before)})',
             "disable 2", "stepi",
             f'printf "IMPORT_AFTER %d\\n", ((unsigned long long)$pc == {M.address(copy, "after_word_store")} && {R.bytes_at(target, after)} && {R.bytes_at(other, other_before)} && {R.bytes_at("$source", source)} && {guards})',
             "enable 3", "continue"]
    first, second = (changed, source) if replica == "first" else (source, changed)
    cmds += [f'printf "IMPORT_PAIR_RETURN %d\\n", ($al == 0 && {R.bytes_at("$first", first)} && {R.bytes_at("$second", second)} && {R.bytes_at("$source", source)} && {guards})',
             "disable 3", "continue"]
    return cmds, test


def validate(text, width, owner, replica, byte, case):
    test = identity(width, owner, replica, byte, case)
    markers = ["ENTRY", "BEFORE", "VALUE", "AFTER", "PAIR_RETURN"]
    if re.findall(r"^IMPORT_[^\r\n]*", text, re.M) != ["IMPORT_" + m + " 1" for m in markers]:
        raise ValueError("import-store checkpoints unconfirmed")
    prefix = "BRYNJA_IMPORT_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", text, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_WIDTH={width}",
        prefix + "_SOURCE_AND_GUARDS_INTACT", prefix + "_STORAGE_CLEARED",
        prefix + ("_ACCEPTED" if case == "baseline" else "_REJECTED"),
    ]:
        raise ValueError("import outcome or cleanup unconfirmed")
    if (text.count("Hardware assisted breakpoint ") != 3 or text.count("hit Breakpoint ") != 3
            or test not in text or text.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or text.count("exited normally") != 1):
        raise ValueError("import-store execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    mapping, _unused_compute = C.map_sites(dump)
    groups = []
    for width in WIDTHS:
        for owner in OWNERS:
            for replica in C.REPLICAS:
                counts = {case: 0 for case in CASES}
                for case in CASES:
                    for byte in ([0] if case == "baseline" else range(width)):
                        experiment, test = commands(mapping, width, owner, replica, byte, case)
                        argv = [gdb, "-q", "-nx", "-batch"]
                        for command in experiment:
                            argv += ["-ex", command]
                        argv += ["--args", str(binary), "--exact", test, "--nocapture"]
                        try:
                            run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                            validate(run.stdout + run.stderr, width, owner, replica, byte, case)
                        except (ValueError, subprocess.SubprocessError) as error:
                            raise ValueError(f"unconfirmed AES-{width*8} {owner} {replica} byte-{byte} {case}") from error
                        counts[case] += 1
                groups.append({"width_bits": width*8, "owner": owner, "replica": replica, "counts": counts})
    if binary.read_bytes() != original or len(groups) != 12:
        raise ValueError("artifact changed or import-store campaign incomplete")
    return {"schema": 1, "status": "finite-native-key-import-store-observations", "qualification": "none",
            "binary_sha256": hashlib.sha256(original).hexdigest(), "capture_mapping": mapping, "groups": groups,
            "selection": "Both key replicas, each key byte: XOR 1 in its register lane before the word store. One unchanged baseline per width/owner/replica group.",
            "limits": ["No C1/DC1 bypass, arbitrary replacement values or faults after complement encoding.",
                       "No owner is returned on rejected import; rejection is not retirement of an existing owner.",
                       "Public fixtures and optimized test ELFs only; not production or physical-fault qualification."]}


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
        print("Import-store experiment failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("12 healthy imports and 288 selected rejected imports observed with cleanup.")
        print("FINITE_DEVELOPMENT_OBSERVATIONS; NOT complete fault or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
