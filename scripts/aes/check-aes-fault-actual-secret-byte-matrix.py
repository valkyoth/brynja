#!/usr/bin/env python3
"""Mutate the actual secret destination before either validator readback.

Bounded public-fixture observations on two pinned x86-64 test ELFs only. This
does not exercise C1/DC1 bypasses, physical faults or release artifacts.
Debugger transcripts are captured and not printed.
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
    "secret_destination_map",
    Path(__file__).with_name("check-aes-fault-secret-destination-map.py"))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)
CHECKS = ("forward", "reverse")
OFFSETS = (0x17, 0x30)
ROOT = Path(__file__).resolve().parents[2]
RECORD = ROOT / "assurance/aes-fault-actual-secret-byte-matrix-observations.json"


def expected_cases(positions, checks):
    return [f"aes{width * 8}/{owner}/{path}/{check}/byte{byte}"
            for width in S.RETAINED.WIDTHS
            for owner in S.RETAINED.OWNERS
            for path in ("encrypt", "decrypt")
            for check in checks
            for byte in positions]


def check_record(reports, positions, checks):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate actual-destination record field")
            result[key] = value
        return result

    record = json.loads(RECORD.read_text(encoding="utf-8"),
                        object_pairs_hook=no_duplicates)
    if (type(record) is not dict or record.get("schema") != 1 or
            record.get("status") != "development-actual-secret-byte-grid-observed" or
            record.get("qualification") != "none" or
            record.get("source_stage") != "secret-destination/actual-readback-pair" or
            positions != list(range(16)) or checks != list(CHECKS) or
            len(reports) != 2):
        raise ValueError("actual-destination grid record mismatch")
    expected = expected_cases(positions, checks)
    scope, artifacts = record.get("scope"), record.get("artifacts")
    if (type(scope) is not dict or type(artifacts) is not list or
            len(artifacts) != 2 or any(type(row) is not dict for row in artifacts) or
            scope.get("widths") != [width * 8 for width in S.RETAINED.WIDTHS] or
            scope.get("owners") != ["cached", "operation-local"] or
            scope.get("paths") != ["encrypt-secret", "decrypt-secret"] or
            scope.get("readbacks") != list(CHECKS) or
            scope.get("byte_positions") != positions or
            scope.get("expected_cases_per_artifact") != len(expected)):
        raise ValueError("actual-destination grid population mismatch")
    recorded = {row.get("binary_sha256"): row for row in artifacts}
    if len(recorded) != 2 or set(recorded) != set(S.SHAPES):
        raise ValueError("actual-destination grid artifacts mismatch")
    if ({report.get("binary_sha256") for report in reports
         if type(report) is dict} != set(S.SHAPES)):
        raise ValueError("both distinct actual-destination artifacts required")
    for report in reports:
        row = recorded[report["binary_sha256"]]
        if (row.get("toolchain") != report.get("toolchain") or
                report.get("cases") != expected or
                report.get("confirmed") != len(expected) or
                report.get("unconfirmed") != [] or
                row.get("confirmed") != len(expected) or
                row.get("unconfirmed") != 0):
            raise ValueError("actual-destination grid observation mismatch")


def commands(owner, answer, byte, check):
    if (type(byte) is not int or not 0 <= byte < 16 or
            check not in CHECKS or len(answer) != 16):
        raise ValueError("invalid secret destination mutation")
    changed = bytearray(answer)
    changed[byte] ^= 1
    symbol = owner["symbol"]
    offset = OFFSETS[CHECKS.index(check)]
    selector = CHECKS.index(check)
    address = f"((unsigned long long)&'{S.VALIDATE}'+{offset})"
    values = S.RESULT.equal_words
    return [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *'{symbol}'",
        f"hbreak *('{S.VALIDATE}'+{offset})", "disable 2", "continue",
        "set $caller=(unsigned char*)$rcx",
        'printf "ACTUAL_ENTRY %d\\n", '
        f"($caller != 0 && {S.same_word('$caller', 0x9191919191919191)})",
        "disable 1", "enable 2", "continue",
        "set $primary=(unsigned char*)$rdx",
        "set $secondary=(unsigned char*)$rcx",
        'printf "ACTUAL_PRE %d\\n", '
        f"($pc == {address} && (unsigned char*)$rdi == $caller && "
        f"$rsi == 16 && $r8 == {selector} && "
        f"$caller != $primary && $caller != $secondary && "
        f"$primary != $secondary && {values('$caller', answer)} && "
        f"{values('$primary', answer)} && {values('$secondary', answer)})",
        f"set *($caller+{byte}) = *($caller+{byte}) ^ 1",
        'printf "ACTUAL_MUTATED %d\\n", '
        f"({values('$caller', changed)} && {values('$primary', answer)} && "
        f"{values('$secondary', answer)})",
        "disable 2", "continue",
    ]


def validate(output, width, owner, path):
    if re.findall(r"^ACTUAL_[^\r\n]*", output, re.M) != [
        "ACTUAL_ENTRY 1", "ACTUAL_PRE 1", "ACTUAL_MUTATED 1",
    ]:
        raise ValueError("actual destination mutation boundary unconfirmed")
    prefix = "BRYNJA_" + owner.upper()
    if re.findall(r"^BRYNJA_[^\r\n]*", output, re.M) != [
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_REJECTED_RETIRED",
    ]:
        raise ValueError("actual destination failure outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 2 or
            output.count("hit Breakpoint ") != 2 or
            S.RETAINED.identity(width, owner, path) not in output or
            output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1 or
            output.count("exited normally") != 1):
        raise ValueError("actual destination fixture execution unconfirmed")


def observe(binary, positions, checks, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    shape = S.SHAPES.get(digest)
    if shape is None:
        raise ValueError("unreviewed secret destination artifact")
    if (not positions or any(type(byte) is not int or not 0 <= byte < 16
                             for byte in positions) or len(set(positions)) != len(positions)):
        raise ValueError("invalid byte positions")
    if (not checks or any(check not in CHECKS for check in checks) or
            len(set(checks)) != len(checks)):
        raise ValueError("invalid readback checks")
    dump = subprocess.run(
        [objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
        capture_output=True, text=True, check=True, timeout=30).stdout
    S.inspect(dump, shape)
    cases, failures = [], []
    for width in S.RETAINED.WIDTHS:
        for owner in S.RETAINED.OWNERS:
            for path in ("encrypt", "decrypt"):
                answer = S.RESULT.PLAIN if path == "decrypt" else S.RESULT.CIPHERS[width]
                for check in checks:
                    for byte in positions:
                        label = f"aes{width * 8}/{owner}/{path}/{check}/byte{byte}"
                        cases.append(label)
                        argv = [gdb, "-q", "-nx", "-batch"]
                        for command in commands(shape["owners"][owner], answer, byte, check):
                            argv += ["-ex", command]
                        argv += ["--args", str(binary), "--exact",
                                 S.RETAINED.identity(width, owner, path), "--nocapture"]
                        try:
                            run = subprocess.run(argv, capture_output=True, text=True,
                                                 check=True, timeout=60)
                            validate(run.stdout + run.stderr, width, owner, path)
                        except subprocess.TimeoutExpired:
                            failures.append({"case": label, "reason": "timeout"})
                        except subprocess.CalledProcessError:
                            failures.append({"case": label, "reason": "debugger-exit"})
                        except ValueError:
                            failures.append({"case": label, "reason": "unconfirmed-markers"})
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise ValueError("artifact changed during actual destination matrix")
    return {"toolchain": shape["toolchain"], "binary_sha256": digest,
            "cases": cases, "confirmed": len(cases) - len(failures),
            "unconfirmed": failures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, action="append")
    parser.add_argument("--byte", type=int, choices=range(16), action="append")
    parser.add_argument("--check", choices=CHECKS, action="append")
    parser.add_argument("--check-record", action="store_true")
    args = parser.parse_args()
    try:
        if len(args.binary) != 2:
            raise ValueError("exactly two pinned test ELFs required")
        positions = args.byte if args.byte is not None else list(range(16))
        checks = args.check if args.check is not None else list(CHECKS)
        reports = [observe(binary, positions, checks) for binary in args.binary]
        if {row["binary_sha256"] for row in reports} != set(S.SHAPES):
            raise ValueError("both distinct pinned artifacts required")
        if args.check_record:
            check_record(reports, positions, checks)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Actual secret byte matrix incomplete before case accounting.", file=sys.stderr)
        return 2
    confirmed = sum(row["confirmed"] for row in reports)
    total = sum(len(row["cases"]) for row in reports)
    print(f"Actual secret byte matrix: {confirmed}/{total} cases confirmed on pinned test ELFs.")
    for row in reports:
        for failure in row["unconfirmed"][:4]:
            print(f"UNCONFIRMED: {row['toolchain']} {failure['case']} ({failure['reason']}).")
    print("DEVELOPMENT_ONLY; no bypass, DC1, physical-fault or release qualification.")
    return 0 if confirmed == total else 2


if __name__ == "__main__":
    raise SystemExit(main())
