#!/usr/bin/env python3
"""Selected cached-import decision bypass on trusted public-fixture test ELFs.

Finite development observations, not complete C1/DC1 or production qualification.
No source hooks, executable patches, retries or raw debugger output.
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
    "import_store", Path(__file__).with_name("check-aes-fault-import-store.py"))
I = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(I)
CASES = ("baseline", "bypass", "data", "combined")
SYMBOLS = ("<brynja_crypto::aes::fault_integrity::retained::Keys>::new_with_fixture_profile",
           "brynja_crypto::aes::fault_integrity::retained::Keys::new_with_fixture_profile")


def map_sites(dump):
    mapping, _ = I.C.map_sites(dump)
    headers = re.findall(r"^([0-9a-f]+) <(.+)>:$", dump, re.M)
    found = [(int(address, 16), symbol) for address, symbol in headers
             if re.sub(r"::h[0-9a-f]{16}$", "", symbol) in SYMBOLS]
    if len(found) != 1:
        raise ValueError("missing or ambiguous key validator")
    address, symbol = found[0]
    site = I.R.C.P.TX.body(dump, re.sub(r"::h[0-9a-f]{16}$", "", symbol))
    site["elf_address"] = address
    body = dump.split(f"{address:016x} <{symbol}>:\n", 1)[1]
    body = re.split(r"\n[0-9a-f]+ <", body, maxsplit=1)[0]
    instructions = [(int(a, 16), re.sub(r"\s+", " ", op.strip()))
                    for a, op in re.findall(r"^\s*([0-9a-f]+):\s+(.+)$", body, re.M)]
    decisions = []
    for index in range(3, len(instructions)-7):
        ops = [op for _, op in instructions[index-3:index+8]]
        if (ops[:3] == ["mov %bpl,0x7(%rsp)", "lea 0x7(%rsp),%rdi", "mov $0x1,%esi"]
                and re.fullmatch(r"call [0-9a-f]+ <brynja_core::secret_memory_volatile::zeroize_region_volatile>", ops[3])
                and ops[4] == "cmpb $0x0,0x7(%rsp)" and ops[5].startswith("jne ")
                and ops[6] == "test %bpl,%bpl" and ops[7].startswith("je ")
                and ops[8:11] == ["movb $0x1,0x8(%rbx)", "movq $0x0,(%rbx)", "lea 0x8(%rsp),%rdi"]):
            decisions.append(instructions[index+3][0]-address)
    if len(decisions) != 1:
        raise ValueError("unknown or ambiguous inlined import decision")
    site["decision"] = decisions[0]
    site["decision_register"] = "bpl"
    return mapping, site


def commands(mapping, validator, width, replica, byte, case):
    if case not in CASES or (case in ("baseline", "bypass") and byte != 0):
        raise ValueError("invalid import-bypass selection")
    data = case in ("data", "combined")
    cmds, test = I.commands(mapping, width, "cached", replica, byte,
                            "data" if data else "baseline")
    # The import validator is inlined. Stop at its actual decision, not the
    # standalone Keys::validate symbol used by another path.
    cmds = cmds[:-1]
    at = f"'{validator['symbol']}'"
    cmds += ["delete 1", "delete 2", "delete 3",
             f"hbreak *({at}+{validator['decision']})", "continue"]
    first = bytearray(range(width))
    second = bytearray(range(width))
    if data:
        (first if replica == "first" else second)[byte] ^= 1
    second = bytes(v ^ 255 for v in second)
    guards = (f"*($first-1) == 0x91 && *($second-1) == 0x92 && "
              f"*($first+{width}) == 0x91 && *($second+{width}) == 0x92")
    contents = " && ".join([I.R.bytes_at("$first", bytes(first)),
                             I.R.bytes_at("$second", second),
                             I.R.bytes_at("$source", bytes(range(width))), guards])
    cmds += [f'printf "BYPASS_DECISION %d\\n", ($bpl == {int(data)} && *(unsigned char*)($rsp+7) == 0 && {contents})']
    if case in ("bypass", "combined"):
        cmds += ["set $bpl = 0", 'printf "BYPASS_FORGED %d\\n", ($bpl == 0)']
    cmds += ["disable 4", "continue"]
    return cmds, test


def validate(text, width, replica, byte, case):
    if case not in CASES or (case in ("baseline", "bypass") and byte != 0):
        raise ValueError("invalid import-bypass selection")
    data = case in ("data", "combined")
    test = I.identity(width, "cached", replica, byte, "data" if data else "baseline")
    expected = ["BYPASS_DECISION 1"]
    if case in ("bypass", "combined"):
        expected += ["BYPASS_FORGED 1"]
    if re.findall(r"^BYPASS_[^\r\n]*", text, re.M) != expected:
        raise ValueError("original decision or bypass unconfirmed")
    if (text.count("Hardware assisted breakpoint ") != 4
            or text.count("hit Breakpoint ") != 4):
        raise ValueError("import-bypass execution unconfirmed")
    # Preserve the import runner's strict checks; strip only the additional
    # stops/allocations after independently checking their exact count above.
    lines = text.splitlines()
    for prefix in ("Hardware assisted breakpoint ", "hit Breakpoint "):
        indices = [i for i, line in enumerate(lines) if prefix in line]
        for index in indices[3:]:
            lines[index] = ""
    I.validate("\n".join(lines), width, "cached", replica, byte,
               "data" if data else "baseline")
    if test not in text:
        raise ValueError("incorrect fixture")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    mapping, validator = map_sites(dump)
    groups = []
    for width in I.WIDTHS:
        for replica in I.C.REPLICAS:
            counts = {case: 0 for case in CASES}
            for case in CASES:
                for byte in ([0] if case in ("baseline", "bypass") else range(width)):
                    experiment, test = commands(mapping, validator, width, replica, byte, case)
                    argv = [gdb, "-q", "-nx", "-batch"]
                    for command in experiment:
                        argv += ["-ex", command]
                    argv += ["--args", str(binary), "--exact", test, "--nocapture"]
                    try:
                        run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                        validate(run.stdout + run.stderr, width, replica, byte, case)
                    except (ValueError, subprocess.SubprocessError) as error:
                        raise ValueError(f"unconfirmed AES-{width*8} cached {replica} byte-{byte} {case}") from error
                    counts[case] += 1
            groups.append({"width_bits": width*8, "replica": replica, "counts": counts})
    if binary.read_bytes() != original:
        raise ValueError("artifact changed")
    return {"schema": 1, "qualification": "none", "status": "finite-cached-import-decision-bypass",
            "binary_sha256": hashlib.sha256(original).hexdigest(), "capture_mapping": mapping,
            "validator": validator, "groups": groups,
            "limits": ["Cached owner only; inlined key-import comparison decision only, not every import check.",
                       "Exact local decision shape with runtime replica/result checks; not a full static constructor review.",
                       "XOR 1 key-copy stores only. No post-complement mutations or complete C1/DC1 coverage.",
                       "Release-profile test ELFs and public fixtures only; no production or physical-fault qualification."]}


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
        print("Import-bypass experiment failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("300 selected cached-import cases observed; NOT complete qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
