#!/usr/bin/env python3
"""Enumerate exact decoded instructions in pinned named bodies; NOT site qualification.

The decoder output is tied to two local test ELFs. Every instruction is a
candidate address, not a claim that it represents a modeled fault site.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RECORD = ROOT / "assurance/aes-fault-instruction-candidates.json"
SPEC = importlib.util.spec_from_file_location(
    "symbol_boundaries", HERE / "check-aes-fault-symbol-boundaries.py")
SYMBOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYMBOLS)


def decode_body(output, start, size):
    if type(start) is not int or type(size) is not int or start < 0 or size <= 0:
        raise ValueError("invalid named-body span")
    rows = []
    for line in output.splitlines():
        match = re.fullmatch(r"\s*([0-9a-fA-F]+):\s+(.+?)\s*", line)
        if match:
            address, operation = int(match[1], 16), match[2]
            if not (start <= address < start + size):
                raise ValueError("decoder escaped named-body span")
            rows.append((address - start, re.sub(r"\s+", " ", operation)))
    if not rows or rows[0][0] != 0 or [offset for offset, _ in rows] != sorted(
            {offset for offset, _ in rows}):
        raise ValueError("missing, duplicated or unordered instruction boundary")
    kinds = {"conditional-jump": [], "direct-or-indirect-jump": [], "call": [],
             "return": [], "setcc": [], "cmovcc": []}
    for offset, operation in rows:
        mnemonic = operation.split(" ", 1)[0]
        if mnemonic.startswith("j") and mnemonic != "jmp":
            kinds["conditional-jump"].append(offset)
        elif mnemonic == "jmp":
            kinds["direct-or-indirect-jump"].append(offset)
        elif mnemonic.startswith("call"):
            kinds["call"].append(offset)
        elif mnemonic.startswith("ret"):
            kinds["return"].append(offset)
        elif mnemonic.startswith("set"):
            kinds["setcc"].append(offset)
        elif mnemonic.startswith("cmov"):
            kinds["cmovcc"].append(offset)
    canonical = "\n".join(f"{offset:x}:{operation}" for offset, operation in rows)
    return {"instruction_count": len(rows),
            "instruction_offsets": [offset for offset, _ in rows],
            "first_offset": rows[0][0], "last_offset": rows[-1][0],
            "decoded_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "candidate_control_offsets": kinds}


def observe(path, objdump="objdump"):
    boundary = SYMBOLS.observe(path)
    path = path.resolve(strict=True)
    bodies = {}
    for family, spans in boundary["bodies"].items():
        found = []
        for span in spans:
            start, size = span["address"], span["size"]
            run = subprocess.run(
                [objdump, "-d", "--no-show-raw-insn", "--demangle",
                 f"--start-address={start}", f"--stop-address={start + size}", str(path)],
                capture_output=True, text=True, check=True, timeout=30)
            found.append({"address": start, "size": size,
                          **decode_body(run.stdout, start, size)})
        bodies[family] = found
    if hashlib.sha256(path.read_bytes()).hexdigest() != boundary["binary_sha256"]:
        raise ValueError("artifact changed during instruction enumeration")
    return {"toolchain": boundary["toolchain"],
            "binary_sha256": boundary["binary_sha256"], "bodies": bodies}


def check_record(rows):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate instruction record field")
            result[key] = value
        return result

    record = json.loads(RECORD.read_text(encoding="utf-8"),
                        object_pairs_hook=no_duplicates)
    if (type(record) is not dict or
            set(record) != {"schema", "status", "qualification", "source_inventory",
                            "boundary_record", "runner", "artifacts", "limits"} or
            record["schema"] != 1 or
            record["status"] != "decoded-candidates-only" or
            record["qualification"] != "none" or
            record["source_inventory"] != "assurance/aes-fault-sites.json" or
            record["boundary_record"] != "assurance/aes-fault-symbol-boundaries.json" or
            record["runner"] != "scripts/aes/check-aes-fault-instruction-candidates.py" or
            record["artifacts"] != rows or not record["limits"]):
        raise ValueError("instruction candidate record drift")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, action="append")
    parser.add_argument("--check-record", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        if len(args.binary) != 2:
            raise ValueError("exactly two pinned test ELFs required")
        rows = [observe(path) for path in args.binary]
        if {row["binary_sha256"] for row in rows} != set(SYMBOLS.PINNED):
            raise ValueError("both distinct pinned test ELFs required")
        if args.check_record:
            check_record(rows)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Instruction candidate enumeration incomplete; no qualification.",
              file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(rows, sort_keys=True))
    else:
        count = sum(body["instruction_count"] for row in rows
                    for spans in row["bodies"].values() for body in spans)
        print(f"Decoded candidates: {count} instruction instances across two exact test ELFs.")
        print("No source-stage correspondence, fault result, bypass pairing or qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
