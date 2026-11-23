"""Run the direct or incremental RV64 GHASH tests on three checked QEMU models."""
import argparse
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "aes_riscv", ROOT / "scripts/aes/check-aes-riscv.py")
RV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RV)


def incremental(cargo, env, logs, model):
    check = "rv64::emulated_owner_respects_reported_features"
    crypto = [*cargo, "-p", "brynja-crypto", "--features", "hazmat-ghash,cpu,hazmat-aes-block"]
    if model == "neither":
        out = RV.run([*crypto, "--test", "ghash_field", "--", "--exact", check], env, logs, model)
        RV.STATIC.validate_tests(out, 1, [f"test {check} ... ok"])
        return
    field = RV.run([*crypto, "--test", "ghash_field"], env, logs, model + "-field")
    RV.STATIC.validate_tests(field, 16, [f"test {name} ... ok" for name in (
        check, "rv64::native_blocks_match_wire_oracle_at_every_split",
        "rv64::partial_block_never_executes_a_product_or_releases_output",
        "scalar_aes::aes128", "scalar_aes::aes192", "scalar_aes::aes256")])
    lifecycle = RV.run([*crypto, "--test", "ghash_lifecycle"], env, logs, model + "-lifecycle")
    RV.STATIC.validate_tests(lifecycle, 4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("toolchain", choices=("1.90.0", "1.100.0"))
    parser.add_argument("--incremental", action="store_true")
    options = parser.parse_args()
    version = options.toolchain
    for name in (*RV.REJECT_ENV, "QEMU_CPU", "BRYNJA_GHASH_RV64_MODEL"):
        if os.environ.get(name):
            raise ValueError(f"remove ambient {name}")
    qemu, linker, sysroot = RV.platform_config()
    base = ROOT / "target/ghash-rv64"
    base.mkdir(parents=True, exist_ok=True)
    logs = Path(tempfile.mkdtemp(prefix=version + "-", dir=base))
    env = dict(os.environ, RUSTUP_AUTO_INSTALL="0", RUSTFLAGS="--cfg brynja_cpu_evidence",
               CARGO_TARGET_DIR=str(base / ("build-" + version)),
               CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=linker)
    cargo = ["cargo", "+" + version, "test", "--locked", "--offline", "--release",
             "--target", RV.TARGET, "--no-default-features"]
    if options.incremental:
        env["RUSTFLAGS"] += " --cfg brynja_ghash_rv64_evidence"
    check = "ghash_rv64::check_emulated_extensions"
    for model, isa in (
        ("both", "zbc=true,zbkc=true,zkne=false,zknd=false"),
        ("zbkc", "zbc=false,zbkc=true,zkne=false,zknd=false"),
        ("neither", "zbc=false,zbkc=false,zkne=true,zknd=true"),
    ):
        env["BRYNJA_GHASH_RV64_MODEL"] = model
        env["CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER"] = shlex.join(
            RV.execution(qemu, sysroot, "rv64," + isa))
        if options.incremental:
            incremental(cargo, env, logs, model)
            continue
        args = (["--", "--exact", check, "--ignored"] if model == "neither" else
                ["ghash_rv64::", "--", "--include-ignored"])
        output = RV.run([*cargo, "-p", "brynja-crypto-cpu", "--lib", *args], env, logs, model)
        RV.STATIC.validate_tests(output, 1 if model == "neither" else 6,
                                 [f"test {check} ... ok"])
    scope = "INCREMENTAL" if options.incremental else "FIELD"
    print(f"GHASH_RV64_{scope}_PASS: {version}; emulated both, Zbkc alone, AES without CLMUL")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"RV64 GHASH check failed: {exc}") from exc
