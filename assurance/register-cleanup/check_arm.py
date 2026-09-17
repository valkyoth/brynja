#!/usr/bin/env python3
"""Arm prototype only: compiler boundaries and QEMU register observers."""
import argparse
from pathlib import Path
import re
import shutil
import tempfile

from check import ROOT, clean_env, run, configure, feature_args

GP = (4, 5, 6, 7, 9)
VECTOR = (*range(8), *range(16, 21))
ERASE = tuple(f'"mov x{i}, xzr",' for i in GP) + tuple(f'"movi v{i}.16b, #0",' for i in VECTOR)
POISON = "\n".join(f'"mov x{i}, #-1",' for i in GP) + "\n" + "\n".join(
    f'"movi v{i}.16b, #255",' for i in VECTOR
)
SHA256 = False


def asm_check(text, *, keccak=False, batch256=False, batch512=False):
    text = re.sub(r"(?m)^\s*(?://|;)\s*BRYNJA_", "// BRYNJA_", text)
    text = re.sub(r"movi\.16b\s+v([0-9]+),", r"movi v\1.16b,", text)
    if text.count("// BRYNJA_SECRET_BEGIN") != 1 or text.count("// BRYNJA_SECRET_END") != 1:
        raise ValueError("missing or ambiguous Arm secret boundary")
    before, rest = text.split("// BRYNJA_SECRET_BEGIN")
    body, after = rest.split("// BRYNJA_SECRET_END")
    if len(re.findall(r"(?m)^\s*ret\s*$", text)) != 1:
        raise ValueError("missing or additional Arm return")
    end = re.search(r"(?m)^\s*ret\s*$", after)
    if end is None:
        raise ValueError("Arm return precedes erasure")
    after = after[:end.end()]
    active, cleanup = body.split("// BRYNJA_REGISTER_ERASE")
    if re.search(r"\b(?:sp|wsp|x29|x30|fp|lr|bl|blr|br|ret)\b", body):
        raise ValueError("Arm secret block touches stack or escapes")
    for i in GP:
        if not re.search(rf"\bmov\s+x{i},\s*xzr\b", cleanup):
            raise ValueError("missing Arm integer erasure")
    for i in VECTOR:
        if not re.search(rf"\bmovi\s+v{i}\.16b,\s*#0\b", cleanup):
            raise ValueError("missing Arm vector erasure")
    operations = [line.strip() for line in cleanup.splitlines() if line.strip() and not line.lstrip().startswith(("//", ";"))]
    if (len(operations) != len(GP) + len(VECTOR) + 1 or not re.fullmatch(r"cmp\s+xzr,\s*xzr", operations[-1])
            or any(not re.match(r"(?:mov|movi)\s", op) for op in operations[:-1])):
        raise ValueError("unexpected Arm post-computation operation")
    algorithm, rounds = ('256', 1) if SHA256 else ('512', 4)
    if batch256 or batch512:
        if len(re.findall(r'\bld1r\b', active)) != 1:
            raise ValueError("Arm batch constant broadcast absent")
    elif keccak:
        if len(re.findall(r'\bbcax\b', active)) != 2:
            raise ValueError("Arm Keccak instructions absent")
    elif len(re.findall(r'\bsha' + algorithm + r'h\b', active)) != rounds or len(re.findall(r'\bsha' + algorithm + r'h2\b', active)) != rounds:
        raise ValueError("Arm dedicated rounds absent")
    for area in (before, after):
        lines = area.splitlines()
        for index, line in enumerate(lines):
            op = line.strip()
            if not op or op.startswith((".", "//", ";")) or op.endswith(":"):
                continue
            if re.fullmatch(r'"?@feat\.00"? = [0-9]+', op):
                continue
            branch = re.fullmatch(r"b\s+([.A-Za-z_][.A-Za-z_0-9]*)", op)
            if branch and any(later.strip() == branch[1] + ":" for later in lines[index + 1:]):
                # Unoptimized pointer conversion may use forward basic blocks;
                # the target must stay on this same side of the secret boundary.
                continue
            if not re.match(r"(?:mov|sub|add|str|ldr|stp|ldp|ret)\b", op):
                raise ValueError("unreviewed Arm compiler operation outside boundary: " + op)
            for address in re.findall(r"\[[^]]*\]", op):
                if not re.fullmatch(r"\[(?:sp|x29)(?:, #?-?[0-9]+)?\]", address):
                    raise ValueError("non-stack Arm memory outside boundary: " + op)


def codegen():
    for compiler in ("1.90.0", "1.98.1"):
        targets = ["aarch64-unknown-linux-musl", "aarch64-apple-darwin", "aarch64-apple-ios", "aarch64-linux-android"]
        if compiler == "1.98.1":
            targets.append("aarch64-pc-windows-msvc")
        for target in targets:
            for optimized in (False, True):
                with tempfile.TemporaryDirectory(prefix="brynja-arm-register-codegen-") as directory:
                    env = clean_env()
                    env["CARGO_TARGET_DIR"] = directory
                    run(["cargo", "+" + compiler, "rustc", "--locked", "--offline", "--lib",
                         "--manifest-path", str(ROOT / "Cargo.toml"), *feature_args(), "--target", target,
                         *(["--release"] if optimized else []), "--", "--emit=asm"], env)
                    files = list(Path(directory).glob(f"{target}/*/deps/*.s"))
                    if len(files) != 1:
                        raise ValueError("missing/ambiguous Arm emitted assembly")
                    text = re.sub(r"(?m)^\s*(?://|;)\s*BRYNJA_", "// BRYNJA_", files[0].read_text())
                    asm_check(text)
                    for marker, insert in (
                        ("// BRYNJA_SECRET_BEGIN", "ldr x4, [x0]\n// BRYNJA_SECRET_BEGIN"),
                        ("// BRYNJA_REGISTER_ERASE", "str x4, [sp]\n// BRYNJA_REGISTER_ERASE"),
                        ("// BRYNJA_SECRET_END", "ldr x4, [x0]\n// BRYNJA_SECRET_END"),
                        ("// BRYNJA_SECRET_END", "// BRYNJA_SECRET_END\nldr x4, [x0]"),
                    ):
                        try:
                            asm_check(text.replace(marker, insert))
                        except ValueError:
                            pass
                        else:
                            raise AssertionError("accepted Arm boundary mutant")
                    print(f"Arm prototype assembly: {compiler} {target} release={optimized}: PASS", flush=True)


def execution(mutations):
    with tempfile.TemporaryDirectory(prefix="brynja-arm-register-mutants-") as directory:
        fixture = Path(directory) / "fixture"
        shutil.copytree(ROOT, fixture, ignore=shutil.ignore_patterns("target", "__pycache__"))
        lib = fixture / "src/lib.rs"
        constants = 'sha256_schedule.rs' if SHA256 else 'sha512_schedule.rs'
        relative = '../../../crates/brynja-crypto-cpu/src/' + constants
        absolute = (ROOT / 'src' / relative).resolve()
        lib.write_text(lib.read_text().replace(relative, absolute.as_posix()))
        source = fixture / "src/arm_sha512.rs"
        production = 'crates/brynja-crypto-cpu/src/aarch64_sha2/secret' + ('256' if SHA256 else '512') + '.rs'
        lib.write_text(lib.read_text().replace(
            '../../../' + production, 'arm_sha512.rs'))
        original = (ROOT.parents[1] / production).read_text()
        poisoned = original.replace('"// BRYNJA_REGISTER_ERASE",', POISON + '\n"// BRYNJA_REGISTER_ERASE",')
        cases = [("unmodified", original, True), ("poison before cleanup", poisoned, True)]
        if mutations:
            prefix, tail = poisoned.split('"// BRYNJA_REGISTER_ERASE",')
            for token in ERASE:
                if tail.count(token) != 1:
                    raise ValueError("stale Arm erasure mutation")
                cases.append((token, prefix + '"// BRYNJA_REGISTER_ERASE",' + tail.replace(token, ""), False))
            cases.append(("scratch erasure removed", original.replace('"str xzr, [{scratch}, x4]",', ""), False))
            before, after = ('"add v0.4s, v0.4s, v2.4s",', '"add v0.4s, v0.4s, v3.4s",') if SHA256 else (
                '"add v0.2d, v0.2d, v16.2d",', '"add v0.2d, v0.2d, v17.2d",')
            cases.append(("wrong feed-forward", original.replace(before, after), False))
        for compiler in ("1.90.0", "1.98.1"):
            for optimized in (False, True):
                for name, contents, expected in cases:
                    source.write_text(contents)
                    env = clean_env()
                    env["RUSTFLAGS"] = "-C linker=rust-lld -C target-feature=+neon,+" + ('sha2' if SHA256 else 'sha3')
                    env["CARGO_TARGET_DIR"] = str(Path(directory) / "build")
                    env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER"] = "qemu-aarch64 -cpu max"
                    result = run(["cargo", "+" + compiler, "test", "--locked", "--offline",
                                  "--manifest-path", str(fixture / "Cargo.toml"), *feature_args(), "--target", "aarch64-unknown-linux-musl",
                                  *(["--release"] if optimized else []), "--", "--nocapture"], env, success=expected)
                    if not expected and (result.returncode == 0 or "test result: FAILED" not in result.stdout):
                        raise AssertionError(f"Arm mutant did not fail in execution: {name}\n{result.stdout}\n{result.stderr}")
                    if expected and ("1024 compression cases" not in result.stdout or "16 guarded placements" not in result.stdout):
                        raise AssertionError("missing Arm execution/bounds marker")
                print(f"Arm prototype observer: {compiler} release={optimized}: {len(cases)} controls/mutants PASS", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", action="store_true")
    parser.add_argument("--mutations", action="store_true")
    parser.add_argument('--sha256', action='store_true')
    args = parser.parse_args()
    SHA256 = args.sha256
    configure(SHA256)
    if SHA256:
        VECTOR = tuple(range(6))
        ERASE = tuple(f'"mov x{i}, xzr",' for i in GP) + tuple(f'"movi v{i}.16b, #0",' for i in VECTOR)
        POISON = '\n'.join(f'"mov x{i}, #-1",' for i in GP) + '\n' + '\n'.join(
            f'"movi v{i}.16b, #255",' for i in VECTOR)
    codegen()
    if args.qemu:
        execution(args.mutations)
    elif args.mutations:
        parser.error("--mutations requires --qemu")
