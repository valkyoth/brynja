#!/usr/bin/env python3
"""Observe operation-local key recapture in pinned x86-64 test ELFs.

This is a read-only, public-fixture mapping check, not fault qualification.
Unknown artifacts and changed instruction shapes fail closed. Debugger output,
registers, and key bytes are never emitted by this runner.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from aes_fault_capture_map import inspect as inspect_copy_chain


SYMBOL = "brynja_crypto::aes::fault_integrity::retained::ephemeral::Ephemeral::compute"
COPY = "brynja_core::secret_memory::copy_secret_region"
TEST_PREFIX = "aes::fault_integrity::retained::probe_tests::import_use_tests::native_import_use_"
PATHS = ("public", "encrypt", "decrypt")
SIZES = (16, 24, 32)

def markers(width):
    result = []
    for replica in ("FIRST", "SECOND"):
        result += [f"LOCAL_{replica}", f"LEAF_{replica}_ENTRY"]
        for index in range(width // 8):
            result += [f"WORD_{replica}_LOAD_{index}",
                       f"WORD_{replica}_AT_STORE_{index}",
                       f"WORD_{replica}_STORED_{index}"]
        result.append(f"LEAF_{replica}_DONE")
    return result

# The reviewed, primitive-only release test artifacts. Evidence-hook builds
# intentionally have different bytes and cannot pass this check.
SHAPES = {
    "bf61f409964ce7678b2a5694e63a5640d4b0a320c76d76866b25c9e95a307baf": {
        "toolchain": "1.100.0", "symbol": "<" + SYMBOL.rsplit("::", 1)[0] + ">::compute",
        "offsets": (0x1b4, 0x1d2), "base": 0xc2e90, "copy": 0x11b9d0,
        "registers": ("%rbp", "%rbx", "%r14", "%r12", "%r15"), "result": "0xff",
        "stack": ("0x70", "0x50"),
    },
    "a11c368e8eccec0e497d336ebe6a9de6381a01dfd3716887c8d69b84efa69c26": {
        "toolchain": "1.90.0", "symbol": SYMBOL,
        "offsets": (0x28d, 0x2ab), "base": 0x108d30, "copy": 0x128170,
        "registers": ("%rbx", "%rbp", "%r15", "%r12", "%r14"), "result": "0x4",
        "stack": ("0x70", "0x30"),
    },
}


def inspect(dump, shape):
    header = re.compile(r"\s*([0-9a-f]+) <(.+)>:\s*")
    instruction = re.compile(r"\s*([0-9a-f]+):\s+(.+?)\s*")
    body = []
    selected = False
    found = 0
    for line in dump.splitlines():
        match = header.fullmatch(line)
        if match:
            selected = match[2] == shape["symbol"]
            if selected:
                found += 1
                if int(match[1], 16) != shape["base"]:
                    raise ValueError("unreviewed recapture function address")
        elif selected and line.strip():
            op = instruction.fullmatch(line)
            if not op:
                raise ValueError("unparsed recapture instruction")
            body.append((int(op[1], 16), re.sub(r"\s+", " ", op[2]).replace(", ", ",")))
    if found != 1:
        raise ValueError("missing or ambiguous recapture function")
    calls = [(i, address) for i, (address, op) in enumerate(body) if COPY in op]
    if len(calls) != 2 or tuple(address - shape["base"] for _, address in calls) != shape["offsets"]:
        raise ValueError("unreviewed recapture calls")
    first_dst, second_dst, length, first_src, second_src = shape["registers"]
    expected = []
    for dst, src, stack in zip((first_dst, second_dst), (first_src, second_src), shape["stack"]):
        expected.append([
            f"lea {stack}(%rsp),{dst}", f"mov {dst},%rdi", f"mov {length},%rsi",
            f"mov {src},%rdx", f"mov {length},%rcx",
            f"call {shape['copy']:x} <{COPY}>", f"cmp ${shape['result']},%al",
        ])
    failures = []
    for (index, _), sequence in zip(calls, expected):
        actual = [op for _, op in body[index - 5:index + 2]]
        if actual != sequence:
            raise ValueError("unreviewed recapture register or result shape")
        branch = re.fullmatch(r"jne ([0-9a-f]+) <.+>", body[index + 2][1])
        if not branch:
            raise ValueError("recapture failure branch missing")
        failures.append(branch[1])
    if len(set(failures)) != 1 or first_src == second_src or first_dst == second_dst:
        raise ValueError("recapture failure or source isolation unconfirmed")


def bytes_at(pointer, data):
    if len(data) not in SIZES:
        raise ValueError("invalid public fixture width")
    return "(" + " && ".join(
        f"*(unsigned long long*)(({pointer})+{n}) == {int.from_bytes(data[n:n + 8], 'little')}ULL"
        for n in range(0, len(data), 8)) + ")"


def word_steps(leaf, replica, data):
    width = len(data)
    result = []
    store = (f"((unsigned long long)&'{leaf['symbol']}' + "
             f"{leaf['events']['word_store']})")
    for index in range(width // 8):
        offset = index * 8
        word = int.from_bytes(data[offset:offset + 8], "little")
        if index:
            result.append("continue")
        result += [
            f'printf "WORD_{replica}_LOAD_{index} %d\\n", ('
            f'$rcx == {offset} && $rdx == {width - offset} && '
            f'(unsigned char*)$rdi == $destination && '
            f'(unsigned char*)$rsi == $source && '
            f'*(unsigned long long*)($source+{offset}) == {word}ULL)',
            "nexti",
            f'printf "WORD_{replica}_AT_STORE_{index} %d\\n", ('
            f'$pc == {store} && $rax == {word}ULL)',
            "nexti",
            f'printf "WORD_{replica}_STORED_{index} %d\\n", ('
            f'*(unsigned long long*)($destination+{offset}) == {word}ULL)',
        ]
    return result


def commands(shape, leaf, width):
    key = bytes(range(width))
    complemented = bytes(value ^ 0xff for value in key)
    first, second = shape["offsets"]
    symbol = shape["symbol"]
    leaf_symbol = leaf["symbol"]
    leaf_entry = leaf["events"]["entry"]
    leaf_return = leaf["events"]["return"]
    disjoint = lambda a, b: f"(({a})+{width} <= ({b}) || ({b})+{width} <= ({a}))"
    checks = [
        f"$rsi == {width}", f"$rcx == {width}",
        disjoint("$first_dst", "$first_src"), bytes_at("$first_src", key),
    ]
    second_checks = [
        f"$rsi == {width}", f"$rcx == {width}",
        bytes_at("$first_src", key), bytes_at("$first_dst", key),
        bytes_at("(unsigned char*)$rdx", complemented),
        disjoint("$first_src", "(unsigned char*)$rdx"),
        disjoint("$first_dst", "(unsigned char*)$rdi"),
        disjoint("$first_src", "(unsigned char*)$rdi"),
        disjoint("$first_dst", "(unsigned char*)$rdx"),
        disjoint("(unsigned char*)$rdi", "(unsigned char*)$rdx"),
    ]
    result = [
        "set debuginfod enabled off", "set pagination off", "set print thread-events off",
        "set disable-randomization off", "starti", "set language c",
        f"hbreak *('{symbol}'+{first})", f"hbreak *('{symbol}'+{second})",
        f"hbreak *('{leaf_symbol}'+{leaf_entry})",
        f"hbreak *('{leaf_symbol}'+{leaf_return})",
        f"hbreak *('{leaf_symbol}'+{leaf['events']['word_load']})",
        "disable 2", "disable 3", "disable 4", "disable 5", "continue",
        "set $first_src=(unsigned char*)$rdx",
        "set $first_dst=(unsigned char*)$rdi",
        f'printf "LOCAL_FIRST %d\\n", ({" && ".join(checks)})',
        "disable 1", "enable 3", "continue",
        f'printf "LEAF_FIRST_ENTRY %d\\n", ((unsigned char*)$rdi == $first_dst && '
        f'(unsigned char*)$rsi == $first_src && $rdx == {width} && '
        f'{bytes_at("$first_src", key)})',
        "set $source=$first_src", "set $destination=$first_dst",
        "disable 3", "enable 5", "continue",
    ]
    result += word_steps(leaf, "FIRST", key)
    result += [
        "disable 5", "enable 4", "continue",
        f'printf "LEAF_FIRST_DONE %d\\n", ('
        f'{bytes_at("$first_src", key)} && {bytes_at("$first_dst", key)})',
        "disable 4", "enable 2", "continue",
        f'printf "LOCAL_SECOND %d\\n", ({" && ".join(second_checks)})',
        "set $second_src=(unsigned char*)$rdx",
        "set $second_dst=(unsigned char*)$rdi", "disable 2", "enable 3", "continue",
        f'printf "LEAF_SECOND_ENTRY %d\\n", ((unsigned char*)$rdi == $second_dst && '
        f'(unsigned char*)$rsi == $second_src && $rdx == {width} && '
        f'{bytes_at("$second_src", complemented)})',
        "set $source=$second_src", "set $destination=$second_dst",
        "disable 3", "enable 5", "continue",
    ]
    result += word_steps(leaf, "SECOND", complemented)
    result += [
        "disable 5", "enable 4", "continue",
        f'printf "LEAF_SECOND_DONE %d\\n", ('
        f'{bytes_at("$second_src", complemented)} && '
        f'{bytes_at("$second_dst", complemented)} && {bytes_at("$first_dst", key)})',
        "disable 4",
        "continue",
    ]
    return result


def validate(output, width, path, test):
    if re.findall(r"^(?:LOCAL|LEAF|WORD)_[^\r\n]*", output, re.M) != [
        marker + " 1" for marker in markers(width)
    ]:
        raise ValueError("recapture checkpoints unconfirmed")
    if re.findall(r"^BRYNJA_IMPORT_USE_[^\r\n]*", output, re.M) != [
        "BRYNJA_IMPORT_USE_EVIDENCE_CFG=false", f"BRYNJA_IMPORT_USE_CASE={width}:{path}",
        "BRYNJA_IMPORT_USE_OWNER_RETURNED", "BRYNJA_IMPORT_USE_SOURCE_AND_GUARDS_INTACT",
        "BRYNJA_IMPORT_USE_STORAGE_CLEARED", "BRYNJA_IMPORT_USE_ACCEPTED",
    ]:
        raise ValueError("recapture fixture identity or outcome unconfirmed")
    if (output.count("Hardware assisted breakpoint ") != 5
            or output.count("hit Breakpoint ") != 6 + 2 * (width // 8) or test not in output
            or output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1
            or output.count("exited normally") != 1):
        raise ValueError("recapture execution unconfirmed")


def observe(binary, objdump="objdump", gdb="gdb"):
    binary = binary.resolve(strict=True)
    original = binary.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or original[18:20] != b"\x3e\x00":
        raise ValueError("requires x86-64 little-endian ELF")
    digest = hashlib.sha256(original).hexdigest()
    shape = SHAPES.get(digest)
    if shape is None:
        raise ValueError("unreviewed recapture artifact")
    dump = subprocess.run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(binary)],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    inspect(dump, shape)
    leaf = inspect_copy_chain(dump)["copy"]
    cases = []
    for width in SIZES:
        for path in PATHS:
            test = TEST_PREFIX + f"{width * 8}_{path}"
            argv = [gdb, "-q", "-nx", "-batch"]
            for command in commands(shape, leaf, width):
                argv += ["-ex", command]
            argv += ["--args", str(binary), "--exact", test, "--nocapture"]
            run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
            validate(run.stdout + run.stderr, width, path, test)
            cases.append(f"aes{width * 8}/{path}")
    if binary.read_bytes() != original or len(cases) != 9:
        raise ValueError("artifact changed or recapture observations incomplete")
    return {
        "schema": 1, "status": "development-local-recapture-observed", "qualification": "none",
        "binary_sha256": digest, "toolchain": shape["toolchain"], "arch": "x86_64",
        "function": shape["symbol"], "call_offsets": list(shape["offsets"]),
        "copy_leaf": {"symbol": leaf["symbol"], "events": leaf["events"],
                      "normalized_sha256": leaf["normalized_sha256"], "shape": leaf["shape"]},
        "baseline_cases": cases,
        "limits": [
            "Public-fixture primitive-only test ELF, not a production or admitted build.",
            "No fault mutations, within-copy corruptions, C1/DC1 combinations or timing tested.",
            "Observed only 16/24/32-byte local key copies on this linked x86-64 artifact.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--json", action="store_true", help="emit bounded metadata, never debugger output")
    args = parser.parse_args()
    try:
        report = observe(args.binary, args.objdump, args.gdb)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print("Local recapture mapping failed: " + detail, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Operation-local recapture and word copies mapped; nine baseline cases; no mutations.")
        print("DEVELOPMENT_MAPPING_ONLY; no fault-model or release qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
