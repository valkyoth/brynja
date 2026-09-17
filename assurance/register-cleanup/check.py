#!/usr/bin/env python3
"""Isolated prototype checks; deliberately NOT wired into release gates."""
import argparse
import itertools
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
PRODUCTION = ROOT.parents[1] / "crates/brynja-crypto-cpu/src/x86_sha512/secret.rs"
FEATURES = "-C target-feature=+sha512,+avx2,+avx"
REGISTERS = ("eax", "ecx", "edx", "r8d", "r9d", "r10d", "r11d")
ERASE = tuple(f'"xor {r}, {r}",' for r in REGISTERS) + tuple(
    f'"vpxor ymm{i}, ymm{i}, ymm{i}",' for i in range(3)
)
POISON = "\n".join(f'"mov {r}, -1",' for r in REGISTERS) + "\n" + "\n".join(
    f'"vpcmpeqd ymm{i}, ymm{i}, ymm{i}",' for i in range(3)
)


def run(command, env=None, *, success=True):
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=180)
    if success and result.returncode:
        raise RuntimeError(f"{command}\n{result.stdout}\n{result.stderr}")
    return result


def asm_check(text):
    # There is exactly one function in this no_std prototype library. Comments
    # delimit the opaque asm boundary, not a claim about all source functions.
    if text.count("# BRYNJA_SECRET_BEGIN") != 1 or text.count("# BRYNJA_SECRET_END") != 1:
        raise ValueError("missing or ambiguous secret boundary")
    before, rest = text.split("# BRYNJA_SECRET_BEGIN")
    body, after = rest.split("# BRYNJA_SECRET_END")
    returns = list(re.finditer(r"(?m)^\s*retq\s*(?:#.*)?$", text))
    if len(returns) != 1:
        raise ValueError("missing or additional machine return")
    end = re.search(r"(?m)^\s*retq\s*(?:#.*)?$", after)
    if end is None:
        raise ValueError("return precedes erasure")
    after = after[:end.end()]
    active, cleanup = body.split("# BRYNJA_REGISTER_ERASE")
    if re.search(r"%(?:rsp|esp|rbp|ebp)\b|\b(?:call\w*|push\w*|pop\w*|ret\w*)\b", body):
        raise ValueError("secret assembly touches the stack or escapes its block")
    for register in REGISTERS:
        if not re.search(rf"\bxorl\s+%{register},\s*%{register}\b", cleanup):
            raise ValueError("missing integer erasure: " + register)
    for i in range(3):
        if not re.search(rf"\bvpxor\s+%ymm{i},\s*%ymm{i},\s*%ymm{i}\b", cleanup):
            raise ValueError("missing vector erasure")
    if active.count("vsha512rnds2") != 2:
        raise ValueError("dedicated round instructions absent")
    # Cleanup must not branch, load, store, spill, call or reload after erasure.
    cleanup_ops = [line.strip() for line in cleanup.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if (len(cleanup_ops) != 11 or not re.fullmatch(r"cmpl\s+%eax,\s*%eax", cleanup_ops[-1])
            or any(not re.match(r"(?:xorl|vpxor)\s", line) for line in cleanup_ops[:-1])):
        raise ValueError("unexpected post-computation operation")
    for area in (before, after):
        for line in area.splitlines():
            op = line.strip()
            if not op or op.startswith((".", "#")) or op.endswith(":"):
                continue
            if re.fullmatch(r"@feat\.00 = [0-9]+", op):
                continue
            # Remaining instructions may only marshal/save public argument
            # pointers or restore ABI-preserved caller registers. Secret loads
            # and all vector/integer secret arithmetic stay inside the block.
            if not re.match(r"(?:pushq|popq|movq|subq|addq|retq|vzeroupper)\b", op):
                raise ValueError("unreviewed compiler operation outside boundary: " + op)
            for address in re.findall(r"\([^)]*\)", op):
                if not re.fullmatch(r"\(%(?:rsp|rbp)\)", address):
                    raise ValueError("non-stack memory access outside boundary: " + op)


def codegen():
    for compiler, targets in (
        ("1.90.0", ("x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-gnu")),
        ("1.98.1", ("x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc")),
    ):
        for target in targets:
            for optimized in (False, True):
                with tempfile.TemporaryDirectory(prefix="brynja-register-codegen-") as directory:
                    env = clean_env()
                    env["CARGO_TARGET_DIR"] = directory
                    run(["cargo", "+" + compiler, "rustc", "--locked", "--offline", "--lib",
                         "--manifest-path", str(ROOT / "Cargo.toml"), "--target", target,
                         *(["--release"] if optimized else []), "--", "--emit=asm"], env)
                    files = list(Path(directory).glob(f"{target}/*/deps/*.s"))
                    if len(files) != 1:
                        raise ValueError("missing/ambiguous emitted assembly")
                    text = re.sub(r"(?m)^\s*#+\s*BRYNJA_", "\t# BRYNJA_", files[0].read_text())
                    asm_check(text)
                    for before, after in (
                        ("# BRYNJA_SECRET_END", "movq (%rdi), %rax\n# BRYNJA_SECRET_END"),
                        ("# BRYNJA_REGISTER_ERASE", "pushq %rax\n# BRYNJA_REGISTER_ERASE"),
                        ("# BRYNJA_SECRET_BEGIN", "movq (%rdi), %rax\n# BRYNJA_SECRET_BEGIN"),
                        ("# BRYNJA_SECRET_END", "# BRYNJA_SECRET_END\nmovq (%rdi), %rax"),
                    ):
                        try:
                            asm_check(text.replace(before, after))
                        except ValueError:
                            pass
                        else:
                            raise AssertionError("accepted assembly boundary mutant")
                    print(f"Prototype assembly: {compiler} {target} release={optimized}: PASS", flush=True)


def clean_env():
    env = dict(os.environ)
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR"):
        env.pop(name, None)
    return env


def execution(sde, mutations):
    with tempfile.TemporaryDirectory(prefix="brynja-register-mutants-") as directory:
        fixture = Path(directory) / "fixture"
        shutil.copytree(ROOT, fixture, ignore=shutil.ignore_patterns("target", "__pycache__"))
        # The shared public round constants are the only checkout dependency.
        lib = fixture / "src/lib.rs"
        absolute = (ROOT / "src/../../../crates/brynja-crypto-cpu/src/sha512_schedule.rs").resolve()
        lib.write_text(lib.read_text().replace("../../../crates/brynja-crypto-cpu/src/sha512_schedule.rs", absolute.as_posix()))
        # The normal fixture directly includes the production kernel. Mutants
        # run on a private copy of those same bytes, never the working kernel.
        lib.write_text(lib.read_text().replace(
            '../../../crates/brynja-crypto-cpu/src/x86_sha512/secret.rs', 'sha512.rs'))
        source = fixture / "src/sha512.rs"
        original = PRODUCTION.read_text()
        source.write_text(original)
        mismatch = run(['cargo', '+1.98.1', 'check', '--locked', '--offline', '--tests',
                        '--manifest-path', str(fixture / 'Cargo.toml'), '--target',
                        'x86_64-unknown-linux-gnu', '--features', 'win64-probe'],
                       clean_env(), success=False)
        if mismatch.returncode == 0 or 'expected "win64" fn, found "C" fn' not in mismatch.stderr:
            raise AssertionError('cross-ABI observer did not reject a mismatched function type')
        poisoned = original.replace('"# BRYNJA_REGISTER_ERASE",', POISON + '\n"# BRYNJA_REGISTER_ERASE",')
        cases = [("unmodified", original, True), ("poison-before-cleanup", poisoned, True)]
        if mutations:
            prefix, tail = poisoned.split('"# BRYNJA_REGISTER_ERASE",')
            for token in ERASE:
                if tail.count(token) != 1:
                    raise ValueError("stale erasure mutation")
                cases.append((token, prefix + '"# BRYNJA_REGISTER_ERASE",' + tail.replace(token, ""), False))
            cases.append(("scratch wipe removed", original.replace('"mov [{scratch} + rcx], rax",\n            "add rcx, 8",\n            "cmp rcx, 704",', '"add rcx, 8",\n            "cmp rcx, 704",'), False))
            cases.append(("wrong final lane mapping", original.replace("0x2028000830381018", "0x2028000830381810"), False))
        for compiler in ("1.90.0", "1.98.1"):
            for optimized, abi in itertools.product((False, True), ("sysv", "win64")):
                for name, contents, expected in cases:
                    source.write_text(contents.replace('extern "C"', 'extern "win64"')
                                      if abi == "win64" else contents)
                    env = clean_env()
                    env["RUSTFLAGS"] = FEATURES
                    env["CARGO_TARGET_DIR"] = str(Path(directory) / "build")
                    env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER"] = str(sde) + " -arl --"
                    result = run(["cargo", "+" + compiler, "test", "--locked", "--offline",
                                  "--manifest-path", str(fixture / "Cargo.toml"), "--target", "x86_64-unknown-linux-gnu",
                                  *(["--features", "win64-probe"] if abi == "win64" else []),
                                  *(["--release"] if optimized else []), "--", "--nocapture"], env, success=expected)
                    if not expected and (result.returncode == 0 or "test result: FAILED" not in result.stdout):
                        raise AssertionError(f"mutant did not fail in execution: {name}\n{result.stdout}\n{result.stderr}")
                    if expected and ("1024 compression cases" not in result.stdout or "16 guarded placements" not in result.stdout):
                        raise AssertionError("missing positive execution/bounds marker")
                print(f"Prototype observer: {compiler} release={optimized} ABI={abi}: {len(cases)} controls/mutants PASS", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sde", type=Path)
    parser.add_argument("--mutations", action="store_true")
    args = parser.parse_args()
    codegen()
    if args.sde:
        execution(args.sde.resolve(), args.mutations)
    elif args.mutations:
        parser.error("--mutations requires --sde")
