"""Rebuild and run the two RVV probe artifacts under QEMU, never collect timing."""
from collections import Counter
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
TARGET = "riscv64gc-unknown-linux-gnu"
TESTS = {"final_batch_and_oversized_records_are_atomic",
         "lanes_carries_every_tail_and_unaligned_buffers",
         "published_vectors_use_parallel_and_tail_paths"}


def run(cmd, cwd, env):
    return subprocess.run(cmd, cwd=cwd, env=env, check=True, timeout=240,
                          stdout=subprocess.PIPE, text=True).stdout


def check(version, root, env):
    base = ["cargo", "+" + version, "test", "--no-run", "--test", "parallel",
            "--manifest-path", str(HERE / "Cargo.toml"), "--offline", "--locked", "--release",
            "--target", TARGET, "--target-dir", str(root / version), "--message-format=json"]
    executables = {}
    for line in run(base, root, env).splitlines():
        item = json.loads(line)
        if item["reason"] == "compiler-artifact" and item.get("executable"):
            executables[item["target"]["name"]] = item["executable"]
    test = executables["parallel"]
    bench = executables["brynja-chacha20-parallel-probe"]
    for binary in (test, bench):
        asm = run(["llvm-objdump", "-d", "--mattr=+v", "--no-show-raw-insn",
                   "--disassemble-symbols=brynja_probe_rvv_rounds", binary], root, env)
        ops = Counter(re.findall(r"^\s*[0-9a-f]+:\s+(\S+)", asm, re.M))
        if (asm.count("<brynja_probe_rvv_rounds>:") != 1 or
                any(ops[k] != n for k, n in {"vsetivli": 1, "vle32.v": 16, "vse32.v": 16,
                    "vadd.vv": 32, "vxor.vv": 32, "vsll.vi": 32, "vsrl.vi": 32, "vor.vv": 32}.items())):
            raise ValueError("missing four-lane packed round body")
    for bits in (128, 256):
        output = run(["qemu-riscv64", "-cpu", f"rv64,v=true,vlen={bits}", test,
                      "--test-threads=1"], root, env)
        if (set(re.findall(r"^test (\w+) \.\.\. ok$", output, re.M)) != TESTS or
                "test result: ok. 3 passed; 0 failed; 0 ignored;" not in output):
            raise ValueError("incomplete RVV test execution")
    refused = run(["qemu-riscv64", "-cpu", "rv64,v=false", bench, "--require-no-v"], root, env)
    if refused.strip() != "RVV unavailable; candidate refused without mutation; scalar ran":
        raise ValueError("no-V negative control did not complete")
    print(f"{version}: RVV VLEN 128/256, no-V refusal and linked rounds passed", flush=True)


def main():
    linker = shutil.which("riscv64-linux-gnu-gcc") or shutil.which("riscv64-suse-linux-gcc")
    if not linker:
        raise ValueError("RV64 GNU cross-linker required")
    with tempfile.TemporaryDirectory(prefix="brynja-chacha-rvv-") as temp:
        root = Path(temp)
        env = {key: os.environ[key] for key in ("HOME", "PATH", "RUSTUP_HOME") if key in os.environ}
        env.update(CARGO_HOME=str(root / "cargo"), RUSTUP_AUTO_INSTALL="0",
                   CARGO_ENCODED_RUSTFLAGS="-Ctarget-feature=+crt-static",
                   CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=linker)
        for version in ("1.90.0", "1.100.0"):
            check(version, root, env)
    print("CHACHA20_RVV_QEMU_COMPLETE")


if __name__ == "__main__":
    main()
