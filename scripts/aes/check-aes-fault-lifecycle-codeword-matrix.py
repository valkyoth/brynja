#!/usr/bin/env python3
"""Bounded local lifecycle-byte replay on two pinned test ELFs, not qualification."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
RECORD = ROOT / "assurance/aes-fault-lifecycle-codeword-matrix-observations.json"
SPEC = importlib.util.spec_from_file_location(
    "lifecycle_complete", Path(__file__).with_name("check-aes-fault-lifecycle-complete.py"))
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)
PINNED = set(L.DEST.SHAPES) & set(L.RESULT_MAP.SHAPES) & set(L.CALLER.SHAPES)


def expected_cases(positions, bits):
    return [f"aes{width * 8}/{owner}/{path}/byte{byte}/bit{bit}"
            for width in L.RETAINED.WIDTHS
            for owner in L.RETAINED.OWNERS
            for path in ("encrypt", "decrypt")
            for byte in positions for bit in bits]


def observe(binary, positions, bits, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    if digest not in PINNED:
        raise ValueError("unreviewed lifecycle artifact")
    if (not positions or not bits or any(type(n) is not int or not 0 <= n < 16
                                      for n in positions) or
            any(type(n) is not int or not 0 <= n < 8 for n in bits) or
            len(positions) != len(set(positions)) or len(bits) != len(set(bits))):
        raise ValueError("invalid byte/bit matrix")
    owner_shape = L.DEST.SHAPES[digest]
    result_shape = L.RESULT_MAP.SHAPES[digest]
    caller_shape = L.CALLER.SHAPES[digest]
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    L.RESULT_MAP.inspect(dump, result_shape, owner_shape)
    L.CALLER.inspect(dump, caller_shape, owner_shape)
    cases, failures = [], []
    for width in L.RETAINED.WIDTHS:
        for owner in L.RETAINED.OWNERS:
            for path in ("encrypt", "decrypt"):
                answer = L.RESULT.PLAIN if path == "decrypt" else L.RESULT.CIPHERS[width]
                for byte in positions:
                    for bit in bits:
                        label = f"aes{width * 8}/{owner}/{path}/byte{byte}/bit{bit}"
                        cases.append(label)
                        argv = [gdb, "-q", "-nx", "-batch"]
                        for command in L.commands(owner_shape["owners"][owner],
                                                  result_shape["owners"][owner],
                                                  caller_shape["callers"][owner],
                                                  answer, byte, bit):
                            argv += ["-ex", command]
                        argv += ["--args", str(binary), "--exact",
                                 L.RETAINED.identity(width, owner, path), "--nocapture"]
                        try:
                            run = subprocess.run(argv, capture_output=True, text=True,
                                                 check=True, timeout=60)
                            L.validate_output(run.stdout + run.stderr, width, owner, path)
                        except subprocess.TimeoutExpired:
                            failures.append({"case": label, "reason": "timeout"})
                        except subprocess.CalledProcessError:
                            failures.append({"case": label, "reason": "debugger-exit"})
                        except ValueError:
                            failures.append({"case": label, "reason": "unconfirmed-markers"})
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise ValueError("artifact changed during matrix")
    return {"toolchain": owner_shape["toolchain"], "binary_sha256": digest,
            "cases": cases, "confirmed": len(cases) - len(failures),
            "unconfirmed": failures}


def check_record(reports, positions, bits):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate lifecycle record field")
            result[key] = value
        return result

    record = json.loads(RECORD.read_text(encoding="utf-8"),
                        object_pairs_hook=no_duplicates)
    if (type(record) is not dict or
            record.get("schema") != 1 or
            record.get("status") != "development-single-bit-grid-observed" or
            record.get("qualification") != "none" or
            record.get("source_stage") != "lifecycle-handoff/completion-state-check" or
            positions != list(range(16)) or bits != list(range(8)) or
            len(reports) != 2):
        raise ValueError("lifecycle grid record mismatch")
    expected = expected_cases(positions, bits)
    scope = record.get("scope")
    artifacts = record.get("artifacts")
    if (type(scope) is not dict or type(artifacts) is not list or
            len(artifacts) != 2 or any(type(row) is not dict for row in artifacts) or
            scope.get("widths") != [width * 8 for width in L.RETAINED.WIDTHS] or
            scope.get("owners") != ["cached", "operation-local"] or
            scope.get("paths") != ["encrypt-secret", "decrypt-secret"] or
            scope.get("byte_positions") != positions or
            scope.get("bit_positions") != bits or
            scope.get("expected_cases_per_artifact") != len(expected)):
        raise ValueError("lifecycle grid record population mismatch")
    recorded = {row.get("binary_sha256"): row for row in artifacts}
    if len(recorded) != 2 or set(recorded) != PINNED:
        raise ValueError("lifecycle grid record population mismatch")
    if ({report.get("binary_sha256") for report in reports
         if type(report) is dict} != PINNED):
        raise ValueError("both distinct lifecycle artifacts required")
    for report in reports:
        if type(report) is not dict:
            raise ValueError("lifecycle grid observation mismatch")
        row = recorded.get(report.get("binary_sha256"))
        if (row is None or row.get("toolchain") != report.get("toolchain") or
                report.get("cases") != expected or
                report.get("confirmed") != len(expected) or
                report.get("unconfirmed") != [] or
                row.get("confirmed") != len(expected) or
                row.get("unconfirmed") != 0):
            raise ValueError("lifecycle grid observation mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, action="append")
    parser.add_argument("--byte", type=int, choices=range(16), action="append")
    parser.add_argument("--bit", type=int, choices=range(8), action="append")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check-record", action="store_true")
    args = parser.parse_args()
    try:
        if len(args.binary) != 2:
            raise ValueError("exactly two pinned test ELFs required")
        positions = args.byte if args.byte is not None else list(range(16))
        bits = args.bit if args.bit is not None else [0]
        reports = [observe(binary, positions, bits) for binary in args.binary]
        if {row["binary_sha256"] for row in reports} != PINNED:
            raise ValueError("both distinct pinned artifacts required")
        if args.check_record:
            check_record(reports, positions, bits)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Lifecycle codeword matrix incomplete before case accounting.", file=sys.stderr)
        return 2
    confirmed = sum(row["confirmed"] for row in reports)
    total = sum(len(row["cases"]) for row in reports)
    if args.json:
        print(json.dumps(reports, sort_keys=True))
    else:
        print(f"Lifecycle codeword matrix: {confirmed}/{total} cases confirmed on pinned test ELFs.")
        for row in reports:
            for failure in row["unconfirmed"][:4]:
                print(f"UNCONFIRMED: {row['toolchain']} {failure['case']} ({failure['reason']}).")
        print("DEVELOPMENT_ONLY; no bypass, DC1, physical-fault or release qualification.")
    return 0 if confirmed == total else 2


if __name__ == "__main__":
    raise SystemExit(main())
