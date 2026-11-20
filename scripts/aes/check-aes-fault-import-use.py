#!/usr/bin/env python3
"""Finite operation-local import/use observations on trusted test ELFs.

Public fixtures only. No source hooks, executable patches, retries or raw dumps.
Not production qualification or complete C1/DC1 coverage.
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
    "import_bypass", Path(__file__).with_name("check-aes-fault-import-bypass.py"))
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
PATHS = ("public", "encrypt", "decrypt")


def identity(width, path, replica, byte, case):
    if path not in PATHS or case not in B.CASES or (case in ("baseline", "bypass") and byte != 0):
        raise ValueError("invalid import-use selection")
    B.I.identity(width, "ephemeral", replica, byte, "data" if case in ("data", "combined") else "baseline")
    return f"aes::fault_integrity::retained::probe_tests::import_use_tests::native_import_use_{width*8}_{path}"


def commands(mapping, validator, width, path, replica, byte, case):
    test = identity(width, path, replica, byte, case)
    # Both fixtures supply the same guarded storage and public key. Reuse the
    # emitted import decision/store protocol, not the cached outcome validator.
    cmds, _ = B.commands(mapping, validator, width, replica, byte, case)
    return cmds, test


def validate(text, width, path, replica, byte, case):
    test = identity(width, path, replica, byte, case)
    if re.findall(r"^IMPORT_[^\r\n]*", text, re.M) != [
        f"IMPORT_{event} 1" for event in ("ENTRY", "BEFORE", "VALUE", "AFTER", "PAIR_RETURN")
    ]:
        raise ValueError("import-use capture unconfirmed")
    bypass = ["BYPASS_DECISION 1"]
    if case in ("bypass", "combined"):
        bypass += ["BYPASS_FORGED 1"]
    if re.findall(r"^BYPASS_[^\r\n]*", text, re.M) != bypass:
        raise ValueError("import-use decision unconfirmed")
    prefix = "BRYNJA_IMPORT_USE_"
    markers = [prefix+"EVIDENCE_CFG=false", prefix+f"CASE={width}:{path}"]
    if case != "data":
        markers += [prefix+"OWNER_RETURNED"]
    markers += [prefix+"SOURCE_AND_GUARDS_INTACT", prefix+"STORAGE_CLEARED"]
    outcome = {"baseline": "ACCEPTED", "bypass": "ACCEPTED",
               "data": "IMPORT_REJECTED", "combined": "USE_REJECTED_RETIRED"}[case]
    markers += [prefix+outcome]
    if re.findall(r"^BRYNJA_[^\r\n]*", text, re.M) != markers:
        raise ValueError("import/use distinction, output behavior or retirement unconfirmed")
    if (text.count("Hardware assisted breakpoint ") != 4
            or text.count("hit Breakpoint ") != 4 or test not in text
            or text.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or text.count("exited normally") != 1):
        raise ValueError("import-use execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    mapping, validator = B.map_sites(dump)
    groups = []
    for width in B.I.WIDTHS:
        for path in PATHS:
            for replica in B.I.C.REPLICAS:
                counts = {case: 0 for case in B.CASES}
                for case in B.CASES:
                    for byte in ([0] if case in ("baseline", "bypass") else range(width)):
                        experiment, test = commands(mapping, validator, width, path, replica, byte, case)
                        argv = [gdb, "-q", "-nx", "-batch"]
                        for command in experiment:
                            argv += ["-ex", command]
                        argv += ["--args", str(binary), "--exact", test, "--nocapture"]
                        try:
                            run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                            validate(run.stdout + run.stderr, width, path, replica, byte, case)
                        except (ValueError, subprocess.SubprocessError) as error:
                            raise ValueError(f"unconfirmed AES-{width*8} operation-local {path} {replica} byte-{byte} {case}") from error
                        counts[case] += 1
                groups.append({"width_bits": width*8, "path": path, "replica": replica, "counts": counts})
    if binary.read_bytes() != original:
        raise ValueError("artifact changed")
    return {"schema": 1, "qualification": "none", "status": "finite-operation-local-import-use",
            "binary_sha256": hashlib.sha256(original).hexdigest(), "capture_mapping": mapping,
            "validator": validator, "groups": groups,
            "limits": ["One inlined import decision bypass and XOR-1 key-copy stores; no bypass of first-use validation.",
                       "Combined cases return an owner but its first operation rejects and retires. Not a guarantee that construction itself rejects every combined fault.",
                       "Retirement is per owner; storage clearing is checked after drop, not asserted immediate at retirement.",
                       "Public fixtures, optimized test ELFs, finite cases only; no production or physical-fault qualification."]}


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
        print("Import-use experiment failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("900 selected operation-local import/use cases observed; NOT complete qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
