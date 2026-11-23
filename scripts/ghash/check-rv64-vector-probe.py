"""Architecture controls only: cross-build a baseline guest and run synthetic KATs in QEMU."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "assurance/ghash-rv64-vector-probe/main.rs"


def main():
    linker = shutil.which("riscv64-linux-gnu-gcc") or shutil.which("riscv64-suse-linux-gcc")
    if not linker:
        raise ValueError("RV64 GNU linker required")
    env = {k: os.environ[k] for k in ("HOME", "RUSTUP_HOME", "PATH") if k in os.environ}
    env["RUSTUP_AUTO_INSTALL"] = "0"
    with tempfile.TemporaryDirectory() as tmp:
        obj = Path(tmp) / "capabilities.o"
        subprocess.run([linker, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-c",
                        str(SRC.with_name("capabilities.c")), "-o", str(obj)], env=env, check=True, timeout=30)
        for version in ("1.90.0", "1.100.0"):
            exe = Path(tmp) / version
            subprocess.run(["rustc", "+" + version, "--edition=2024", "--target=riscv64gc-unknown-linux-gnu",
                            "-Dwarnings", "-O", "-C", "target-feature=+crt-static", "-C", "linker=" + linker,
                            "-C", "link-arg=" + str(obj), str(SRC), "-o", str(exe)], env=env, check=True, timeout=120)
            for model in ("scalar", "vector", "zvkg", "zvbc", "both"):
                vector = model != "scalar"
                for width in ((128, 256) if vector else (0,)):
                    bits = dict(v=vector, zbc=not vector, zbkc=False,
                                zvkg=model in ("zvkg", "both"), zvbc=model in ("zvbc", "both"))
                    cpu = "rv64," + ",".join(f"{k}={str(v).lower()}" for k, v in bits.items())
                    if vector:
                        cpu += f",vlen={width}"
                    run = subprocess.run(["qemu-riscv64", "-cpu", cpu, str(exe), model, str(width)],
                                         env=env, check=True, text=True, stdout=subprocess.PIPE, timeout=30)
                    if run.stdout != f"vector probe passed: {model}\n":
                        raise ValueError("guest completion mismatch")
            print(f"{version}: nine emulated capability and instruction controls passed", flush=True)
    print("GHASH_RV64_VECTOR_PROBE_COMPLETE")


if __name__ == "__main__":
    main()
