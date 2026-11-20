#!/usr/bin/env python3
"""Finite input-capture store/register faults in trusted test ELFs, NOT qualification.

Public FIPS fixtures only. Hardware stops and one instruction step; no executable
patching. Raw debugger output stays captured. No automatic retries.
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
    "capture_map", Path(__file__).with_name("check-aes-fault-capture-map.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
R = M.R
COMPUTE = "brynja_crypto::aes::fault_integrity::retained::Retained::compute"
CASES = ("baseline", "data", "combined")
REPLICAS = ("first", "second")


def map_sites(dump):
    mapping = M.inspect(dump)
    compute = R.C.P.TX.body(dump, re.sub(r"::h[0-9a-f]{16}$", "", R.symbol(dump, COMPUTE)))
    leaf = mapping["copy"]
    store = leaf["elf_address"] + leaf["events"]["word_store"]
    instructions = [(int(m[1], 16), re.sub(r"\s+", " ", m[2])) for m in re.finditer(
        r"^\s*([0-9a-fA-F]+):\s+([^\r\n]+)", dump, re.M)]
    indices = [i for i, (address, _) in enumerate(instructions) if address == store]
    if len(indices) != 1 or indices[0] + 1 >= len(instructions):
        raise ValueError("missing/ambiguous copy store successor")
    address, op = instructions[indices[0] + 1]
    if address <= store or op != "add $0x8,%rcx":
        raise ValueError("unreviewed copy store successor")
    leaf["events"]["after_word_store"] = address - leaf["elf_address"]
    return mapping, compute


def selection(width, owner, path, replica, byte, case):
    test = R.C.identity(width, path, "baseline", owner)
    if replica not in REPLICAS or type(byte) is not int or not 0 <= byte < 16 or case not in CASES:
        raise ValueError("invalid copy-store selection")
    if case == "baseline" and byte != 0:
        raise ValueError("baseline selects byte zero only")
    return test


def commands(mapping, compute, width, owner, path, replica, byte, case):
    test = selection(width, owner, path, replica, byte, case)
    source = bytes.fromhex(R.C.ANSWERS[width] if path == "decrypt" else R.C.PLAIN)
    answer = bytes.fromhex(R.C.PLAIN if path == "decrypt" else R.C.ANSWERS[width])
    faulty = case != "baseline"
    changed = bytearray(source)
    if faulty:
        changed[byte] ^= 1
    changed = bytes(changed)
    word_offset = byte // 8 * 8
    word = int.from_bytes(source[word_offset:word_offset + 8], "little")
    mask = 1 << ((byte % 8) * 8)
    proposed = word ^ mask if faulty else word
    before = source[:word_offset] + bytes(16 - word_offset)
    after = changed[:word_offset + 8] + bytes(8 - word_offset)
    other_before = bytes(16) if replica == "first" else source
    target = "$" + replica
    other = "$second" if replica == "first" else "$first"
    capture, copy = mapping["capture"], mapping["copy"]
    cmds = ["set debuginfod enabled off", "set pagination off", "set print thread-events off",
            "set disable-randomization off", "starti", "set language c",
            f"hbreak *'{compute['symbol']}'", f"hbreak *{M.at(capture, 'entry')}",
            f"hbreak *{M.at(copy, 'word_store')}",
            f"hbreak *('{compute['symbol']}'+{compute['ret']})",
            "disable 2", "disable 3", "disable 4", "continue",
            "set $input=(unsigned char*)$rsi", "set $primary=(unsigned char*)$rdx",
            "set $secondary=(unsigned char*)$rcx", "set $completion=(unsigned char*)$r9"]
    checks = [R.bytes_at("$input", source)] + [R.bytes_at(p, bytes(16)) for p in (
        "$primary", "$secondary", "$completion")]
    checks += [f"($r8 & 255) == {int(path == 'decrypt')}"]
    pointers = ("$input", "$primary", "$secondary", "$completion")
    checks += [f"({a}+16 <= {b} || {b}+16 <= {a})" for i, a in enumerate(pointers) for b in pointers[i+1:]]
    cmds += ['printf "STORE_ENTRY %d\\n", (' + " && ".join(checks) + ")",
             "delete 1", f"hbreak *{M.at(capture, 'return')}", "disable 5", "enable 2", "continue",
             "set $first=(unsigned char*)$rdx", "set $second=(unsigned char*)$r8"]
    pointers = ("$input", "$first", "$second", "$primary", "$secondary", "$completion")
    checks = ["(unsigned char*)$rdi == $input", "$rsi == 16", "$rcx == 16", "$r9 == 16",
              R.bytes_at("$first", bytes(16)), R.bytes_at("$second", bytes(16))]
    checks += [f"({a}+16 <= {b} || {b}+16 <= {a})" for i, a in enumerate(pointers) for b in pointers[i+1:]]
    cmds += ['printf "STORE_CAPTURE %d\\n", (' + " && ".join(checks) + ")", "disable 2", "enable 3"]
    # Every input is 16 bytes: two word stores in first, then two in second.
    skip = (2 if replica == "second" else 0) + byte // 8
    if skip:
        cmds.append(f"ignore 3 {skip}")
    cmds += ["continue"]
    checks = [f"(unsigned long long)$pc == {M.address(copy, 'word_store')}",
              f"(unsigned char*)$rdi == {target}", "(unsigned char*)$rsi == $input",
              f"$rcx == {word_offset}", f"$rdx == {16 - word_offset}", f"$rax == {word}ULL",
              R.bytes_at("$input", source), R.bytes_at(target, before), R.bytes_at(other, other_before)]
    cmds += ['printf "STORE_BEFORE %d\\n", (' + " && ".join(checks) + ")"]
    if faulty:
        cmds.append(f"set $rax = $rax ^ {mask}ULL")
    cmds += [f'printf "STORE_VALUE %d\\n", ($rax == {proposed}ULL && {R.bytes_at("$input", source)} && {R.bytes_at(target, before)})',
             "disable 3", "stepi",
             f'printf "STORE_AFTER %d\\n", ((unsigned long long)$pc == {M.address(copy, "after_word_store")} && {R.bytes_at(target, after)} && {R.bytes_at(other, other_before)} && {R.bytes_at("$input", source)})',
             "enable 5", "continue"]
    first, second = (changed, source) if replica == "first" else (source, changed)
    cmds += [f'printf "STORE_PAIR_RETURN %d\\n", ($al == 0 && {R.bytes_at("$first", first)} && {R.bytes_at("$second", second)} && {R.bytes_at("$input", source)})',
             "disable 5", "enable 4", "continue"]
    result = bytes(16) if faulty else answer
    completion = bytes(16) if faulty else bytes([0x69]) * 16
    cmds += [f'printf "STORE_COMPUTE_RETURN %d\\n", ($al == {int(faulty)} && {R.bytes_at("$primary", result)} && {R.bytes_at("$secondary", result)} && {R.bytes_at("$completion", completion)})']
    if case == "combined":
        cmds += ["set $al = 0", 'printf "STORE_FORGED %d\\n", ($al == 0)']
    return cmds + ["disable 4", "continue"], test


def validate(text, width, owner, path, replica, byte, case):
    test = selection(width, owner, path, replica, byte, case)
    markers = ["STORE_ENTRY", "STORE_CAPTURE", "STORE_BEFORE", "STORE_VALUE", "STORE_AFTER",
               "STORE_PAIR_RETURN", "STORE_COMPUTE_RETURN"]
    if case == "combined":
        markers.append("STORE_FORGED")
    if re.findall(r"^STORE_[^\r\n]*", text, re.M) != [m + " 1" for m in markers]:
        raise ValueError("copy-store checkpoints unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", text, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}", prefix + "_STORAGE_CLEARED",
        prefix + ("_ACCEPTED" if case == "baseline" else "_REJECTED_RETIRED"),
    ]:
        raise ValueError("copy-store owner outcome unconfirmed")
    if (text.count("Hardware assisted breakpoint ") != 5 or text.count("hit Breakpoint ") != 5
            or test not in text or text.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or text.count("exited normally") != 1):
        raise ValueError("copy-store execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    mapping, compute = map_sites(dump)
    groups = []
    for width in R.C.ANSWERS:
        for owner in R.C.OWNERS:
            for path in R.C.PATHS:
                for replica in REPLICAS:
                    counts = {case: 0 for case in CASES}
                    for case in CASES:
                        for byte in ([0] if case == "baseline" else range(16)):
                            experiment, test = commands(mapping, compute, width, owner, path, replica, byte, case)
                            argv = [gdb, "-q", "-nx", "-batch"]
                            for command in experiment:
                                argv += ["-ex", command]
                            argv += ["--args", str(binary), "--exact", test, "--nocapture"]
                            try:
                                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                                validate(run.stdout + run.stderr, width, owner, path, replica, byte, case)
                            except (ValueError, subprocess.SubprocessError) as error:
                                raise ValueError(f"unconfirmed AES-{width * 8} {owner} {path} {replica} byte-{byte} {case}") from error
                            counts[case] += 1
                    groups.append({"width_bits": width * 8, "owner": owner, "path": path,
                                   "replica": replica, "counts": counts})
    if binary.read_bytes() != original or len(groups) != 36:
        raise ValueError("artifact changed or copy-store campaign incomplete")
    return {"schema": 1, "status": "finite-native-input-store-observations", "qualification": "none",
            "binary_sha256": hashlib.sha256(original).hexdigest(), "capture_mapping": mapping,
            "compute": compute, "groups": groups,
            "selection": "Each input replica, byte 0..15: XOR 1 in the selected RAX lane immediately before its word store; data-only and data plus forged Retained::compute success. One unchanged baseline per group.",
            "limits": ["No key-import stores, arbitrary values, other data sites or other bypasses.",
                       "The failed computation is rejected before producing AES results; completion stays unmarked.",
                       "Test ELFs and public fixtures only; not physical-fault, full D3/DC1 or production qualification."]}


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
        print("Copy-store experiment failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("36 baselines, 576 input-store mutations and 576 selected combined cases observed.")
        print("FINITE_DEVELOPMENT_OBSERVATIONS; NOT complete fault or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
