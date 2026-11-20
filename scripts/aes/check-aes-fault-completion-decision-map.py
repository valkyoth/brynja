#!/usr/bin/env python3
"""Pin candidate completion-check instructions in two exact test ELFs.

This maps one source stage to emitted instructions. It does not demonstrate
instruction-skip, C1/DC1 or fault-resistant release behavior.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RECORD = ROOT / "assurance/aes-fault-completion-decision-map.json"
SPEC = importlib.util.spec_from_file_location(
    "instruction_candidates", HERE / "check-aes-fault-instruction-candidates.py")
INSTR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTR)
POINTS = {
    "a11c368e8eccec0e497d336ebe6a9de6381a01dfd3716887c8d69b84efa69c26": {
        "copy-call": (0x29, "call", "copy_secret_region"),
        "copy-status": (0x2e, "cmp", ""),
        "expected-codeword": (0x34, "movabs", "0x3c3c3c3c3c3c3c3c"),
        "upper-half-xor": (0x43, "xor", ""),
        "lower-half-xor": (0x46, "xor", ""),
        "combine-mismatch": (0x4a, "or", ""),
        "mismatch-flag": (0x4d, "setne", ""),
        "state-select": (0x81, "je", ""),
        "state-store": (0x93, "movups", "(%rbx)"),
        "result-return": (0xa2, "ret", ""),
    },
    "bf61f409964ce7678b2a5694e63a5640d4b0a320c76d76866b25c9e95a307baf": {
        "copy-call": (0x27, "call", "copy_secret_region"),
        "copy-status": (0x2c, "cmp", ""),
        "expected-codeword": (0x32, "movabs", "0x3c3c3c3c3c3c3c3c"),
        "upper-half-xor": (0x41, "xor", ""),
        "lower-half-xor": (0x44, "xor", ""),
        "combine-mismatch": (0x48, "or", ""),
        "mismatch-flag": (0x4b, "setne", ""),
        "state-select": (0x5a, "je", ""),
        "state-store": (0x6c, "movups", "(%rbx)"),
        "result-return": (0x7b, "ret", ""),
    },
}
CHECK_STAGE = {"copy-call", "copy-status", "expected-codeword", "upper-half-xor",
               "lower-half-xor", "combine-mismatch", "mismatch-flag"}


def inspect(binary, objdump="objdump"):
    observed = INSTR.observe(binary, objdump)
    digest = observed["binary_sha256"]
    if digest not in POINTS:
        raise ValueError("unreviewed completion artifact")
    body = observed["bodies"]["lifecycle-handoff"][0]
    start, size = body["address"], body["size"]
    run = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", "--demangle",
         f"--start-address={start}", f"--stop-address={start + size}",
         str(binary.resolve(strict=True))],
        capture_output=True, text=True, check=True, timeout=30)
    decoded = {}
    for line in run.stdout.splitlines():
        match = re.fullmatch(r"\s*([0-9a-fA-F]+):\s+(.+?)\s*", line)
        if match:
            decoded[int(match[1], 16) - start] = match[2].split(" #", 1)[0]
    if set(decoded) != set(body["instruction_offsets"]):
        raise ValueError("completion instruction population changed")
    points = {}
    for name, (offset, mnemonic, operand) in POINTS[digest].items():
        operation = decoded.get(offset, "")
        if not (operation == mnemonic or operation.startswith(mnemonic + " ")):
            raise ValueError("completion operation changed")
        if operand and operand not in operation:
            raise ValueError("completion operand changed")
        points[name] = offset
    if len(set(points.values())) != len(points):
        raise ValueError("duplicate completion instruction")
    return {"toolchain": observed["toolchain"], "binary_sha256": digest,
            "body_address": start, "body_decoded_sha256": body["decoded_sha256"],
            "completion_state_check": {name: points[name] for name in CHECK_STAGE},
            "shared_state_select_write": {name: points[name]
                                          for name in ("state-select", "state-store")},
            "result_return": points["result-return"]}


def check_record(rows):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate decision record field")
            result[key] = value
        return result

    record = json.loads(RECORD.read_text(encoding="utf-8"),
                        object_pairs_hook=no_duplicates)
    if (type(record) is not dict or
            set(record) != {"schema", "status", "qualification", "source_stage",
                            "instruction_record", "artifacts", "limits"} or
            record["schema"] != 1 or record["status"] != "candidate-stage-map" or
            record["qualification"] != "none" or
            record["source_stage"] != "lifecycle-handoff/completion-state-check" or
            record["instruction_record"] != "assurance/aes-fault-instruction-candidates.json" or
            record["artifacts"] != rows or not record["limits"]):
        raise ValueError("completion decision record drift")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, action="append")
    parser.add_argument("--check-record", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        if len(args.binary) != 2:
            raise ValueError("exactly two pinned test ELFs required")
        rows = [inspect(path) for path in args.binary]
        if {row["binary_sha256"] for row in rows} != set(POINTS):
            raise ValueError("both distinct artifacts required")
        if args.check_record:
            check_record(rows)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Completion decision candidate map incomplete; no qualification.",
              file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(rows, sort_keys=True))
    else:
        print("Completion-state check: seven candidate instructions pinned per test ELF.")
        print("State select/write and return pinned separately; C1/DC1 remains OPEN.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
