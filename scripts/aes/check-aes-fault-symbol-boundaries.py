#!/usr/bin/env python3
"""Locate named bodies in two pinned x86-64 test ELFs; NOT fault qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
RECORD = ROOT / "assurance/aes-fault-symbol-boundaries.json"
PINNED = {
    "a11c368e8eccec0e497d336ebe6a9de6381a01dfd3716887c8d69b84efa69c26": "1.90.0",
    "bf61f409964ce7678b2a5694e63a5640d4b0a320c76d76866b25c9e95a307baf": "1.100.0",
}
FAMILIES = {
    "secondary-expansion": ("brynja_crypto::aes::fault_integrity::schedule::Schedule::expand",),
    "secondary-rounds": ("brynja_crypto::aes::fault_integrity::schedule::Schedule::transform",),
    "import-checks": ("brynja_crypto::aes::fault_integrity::retained::Keys::new_with_fixture_profile",),
    "use-checks": ("brynja_crypto::aes::fault_integrity::retained::Retained::compute",),
    "receipt-observations": ("brynja_crypto::aes::fault_integrity::authorization_model::Candidate::observe",
                             "brynja_crypto::aes::fault_integrity::authorization_model::Candidate::consume"),
    "tentative-write": ("brynja_crypto::aes::fault_integrity::transaction::guarded_write",),
    "lifecycle-handoff": ("brynja_crypto::aes::fault_integrity::transaction::Operation::complete",),
}


def symbol_table(output):
    wanted = {symbol for symbols in FAMILIES.values() for symbol in symbols}
    found = {}
    for line in output.splitlines():
        match = re.fullmatch(r"([0-9a-f]+) ([0-9a-f]+) ([a-zA-Z]) (.+)", line)
        if not match:
            continue
        address, size, kind, name = match.groups()
        canonical = name.replace("<", "").replace(">", "")
        if canonical not in wanted:
            continue
        if canonical in found or kind not in ("t", "T") or int(size, 16) == 0:
            raise ValueError("duplicate or invalid text symbol")
        found[canonical] = {"address": int(address, 16), "size": int(size, 16)}
    if set(found) != wanted:
        raise ValueError("missing exact named body")
    return found


def observe(path, nm="nm"):
    path = path.resolve(strict=True)
    raw = path.read_bytes()
    if raw[:6] != b"\x7fELF\x02\x01" or raw[18:20] != b"\x3e\x00":
        raise ValueError("not an x86-64 little-endian ELF")
    digest = hashlib.sha256(raw).hexdigest()
    if digest not in PINNED:
        raise ValueError("unreviewed test ELF")
    result = subprocess.run([nm, "-S", "-C", "--defined-only", str(path)],
                            capture_output=True, text=True, check=True, timeout=30)
    table = symbol_table(result.stdout)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError("artifact changed during observation")
    return {"toolchain": PINNED[digest], "binary_sha256": digest,
            "bodies": {family: [table[symbol] for symbol in symbols]
                       for family, symbols in FAMILIES.items()}}


def check_record(rows):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate record field")
            result[key] = value
        return result

    record = json.loads(RECORD.read_text(encoding="utf-8"),
                        object_pairs_hook=no_duplicates)
    if (set(record) != {"schema", "status", "qualification", "source_inventory",
                        "runner", "artifacts", "limits"} or
            record.get("schema") != 1 or
            record.get("status") != "partial-named-body-boundaries" or
            record.get("qualification") != "none" or
            record.get("source_inventory") != "assurance/aes-fault-sites.json" or
            record.get("runner") != "scripts/aes/check-aes-fault-symbol-boundaries.py" or
            record.get("artifacts") != rows or
            not record.get("limits")):
        raise ValueError("symbol boundary record does not match exact artifacts")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, action="append")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check-record", action="store_true")
    args = parser.parse_args()
    try:
        if len(args.binary) != 2:
            raise ValueError("exactly two pinned artifacts required")
        rows = [observe(path) for path in args.binary]
        if {row["binary_sha256"] for row in rows} != set(PINNED):
            raise ValueError("require both distinct pinned artifacts")
        if args.check_record:
            check_record(rows)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Symbol-boundary observation incomplete; no qualification.", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(rows, sort_keys=True))
    else:
        print(f"Named-body boundaries observed: {len(FAMILIES)} source families on two pinned test ELFs.")
        print("Only symbol spans; no per-instruction fault-site or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
