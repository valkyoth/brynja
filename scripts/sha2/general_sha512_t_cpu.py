"""Bounded candidate execution, production rejection and injected-KAT controls.

Only temporary evidence builds carry the non-admitting evidence cfg. This is
not runtime CPU detection, a migration guarantee, or a backend admission.
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = "assurance/general-sha512-t-cpu/Cargo.toml"
FOOTER = "candidate=unadmitted; hardened=portable-only; independently_verified=false; fips_validated=false"
CRATES = ("brynja-core", "brynja-hash-core", "brynja-hash-sha2", "brynja-crypto-cpu")


def execute(command, *, root=ROOT, env=None):
    # Commands and checkout are trusted, fixed repository tools. Capture to a
    # temporary file so a broken compiler/runner cannot grow Python's memory.
    with tempfile.TemporaryFile() as stream:
        result = subprocess.run(command, cwd=root, env=env, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=600)
        if stream.tell() > 2_000_000:
            raise ValueError("CPU evidence output exceeds bound")
        stream.seek(0)
        return result.returncode, stream.read().decode("utf-8")


def parse(text, backend):
    lines = [line for line in text.splitlines() if line.startswith(("General SHA-512/t CPU", "t=", "candidate="))]
    if len(lines) != 7 or lines[0] != f"General SHA-512/t CPU acceptance: PASS; parameters=510; cases=4590; backend={backend}" or lines[-1] != FOOTER:
        raise ValueError("incomplete or overstated candidate evidence")
    for t, line in zip((1, 9, 224, 256, 511), lines[1:-1], strict=True):
        match = re.fullmatch(rf"t={t} bytes=16384 operations=32 accelerated_ns=([0-9]+)", line)
        if not match or not 0 < int(match[1]) < 10**15:
            raise ValueError("invalid candidate performance row")
    return "\n".join(lines)


def environment(target_dir, flags, target, runner=None):
    env = dict(os.environ, CARGO_TARGET_DIR=str(target_dir), RUSTFLAGS=flags)
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    env.pop("RUSTC_WRAPPER", None)
    env.pop("RUSTC_WORKSPACE_WRAPPER", None)
    env.pop("CARGO_BUILD_TARGET", None)
    key = "CARGO_TARGET_" + target.upper().replace("-", "_") + "_RUNNER"
    env.pop(key, None)
    if runner:
        env[key] = runner
    return env


def campaign(target, flags, backend, runner=None, *, profiles=("debug", "release"), compiler="1.98.1", mutations=False):
    results = {}
    with tempfile.TemporaryDirectory(prefix="brynja-general-cpu-") as directory:
        temporary = Path(directory)
        env = environment(temporary / "target", flags, target, runner)
        for profile in profiles:
            command = ["cargo", "+" + compiler, "run", "--locked", "--offline", "--manifest-path", FIXTURE,
                       "--target", target, *(["--release"] if profile == "release" else [])]
            # Even with exact CPU features, normal builds must not get a session.
            code, output = execute(command, env=env)
            if not code or 'required SHA-512 CPU candidate unavailable; no fallback' not in output:
                raise ValueError("production admission control failed:\n" + output)
            env["RUSTFLAGS"] = "--cfg brynja_cpu_evidence " + flags
            code, output = execute(command, env=env)
            if code:
                raise ValueError("candidate execution failed:\n" + output)
            results[profile] = parse(output, backend)
            env["RUSTFLAGS"] = flags

        # No production backdoor: inject startup-KAT failure in a disposable
        # copy of the existing dependency closure, then exercise every public
        # method. A compiling, healthy fallback must fail these assertions.
        copy = temporary / "source"
        for name in CRATES:
            shutil.copytree(ROOT / "crates" / name, copy / "crates" / name,
                            ignore=shutil.ignore_patterns("target"))
        for name in ("general-sha512-t", "general-sha512-t-cpu"):
            shutil.copytree(ROOT / "assurance" / name, copy / "assurance" / name,
                            ignore=shutil.ignore_patterns("target"))
        # Workspace-inherited metadata used by the copied packages.
        shutil.copyfile(ROOT / "Cargo.toml", copy / "Cargo.toml")
        source = copy / "crates/brynja-crypto-cpu/src/sha512.rs"
        text = source.read_text()
        before = "Self::construct(backend, false).ok()"
        if text.count(before) != 1:
            raise ValueError("ambiguous KAT injection site")
        source.write_text(text.replace(before, "Self::construct(backend, true).ok()"))
        env["RUSTFLAGS"] = "--cfg brynja_cpu_evidence " + flags
        env["CARGO_TARGET_DIR"] = str(temporary / "quarantine-target")
        for profile in profiles:
            command = ["cargo", "+" + compiler, "run", "--locked", "--offline", "--manifest-path", FIXTURE,
                       "--target", target, *(["--release"] if profile == "release" else [])]
            code, output = execute(command + ["--", "--quarantine"], root=copy, env=env)
            if code or "General SHA-512/t quarantine acceptance: PASS" not in output:
                raise ValueError("quarantine rejection/state-preservation check failed:\n" + output)
            code, output = execute(command, root=copy, env=env)
            if not code or "acceptance failed: Mismatch" not in output:
                raise ValueError("failed KAT did not invalidate positive acceptance:\n" + output)
            if mutations:
                api = copy / "crates/brynja-hash-sha2/src/general/cpu.rs"
                original = api.read_text()
                for before, after in (
                    (".update_with_backend(input, backend)", ".update(input).map_err(|_| Sha512AcceleratedError::MessageTooLong)"),
                    ("self\n            .state\n            .finalize_with_backend(backend)", "Ok::<_, Sha512AcceleratedError>(self.state.finalize())"),
                    (".finalize_bits_with_backend(input, backend)", ".finalize_bits(input).map_err(|_| Sha512AcceleratedError::MessageTooLong)"),
                ):
                    # Only the shared-state call, not a public one-shot caller.
                    if before not in original:
                        raise ValueError("CPU route mutation site absent")
                    try:
                        api.write_text(original.replace(before, after, 1))
                        code, output = execute(command + ["--", "--quarantine"], root=copy, env=env)
                        if not code or "quarantine failed: Mismatch" not in output:
                            raise ValueError("compiled portable-fallback mutation not caught:\n" + output)
                    finally:
                        api.write_text(original)
    return results


def qemu():
    arm = campaign("aarch64-unknown-linux-musl", "-C target-feature=+neon,+sha3 -C linker=rust-lld",
                   "aarch64-sha512", "qemu-aarch64", mutations=True)
    linker = shutil.which("riscv64-linux-gnu-gcc") or shutil.which("riscv64-suse-linux-gcc")
    if not linker:
        raise ValueError("RISC-V cross linker required")
    sysroot = "/usr/riscv64-linux-gnu" if "linux-gnu" in linker else subprocess.check_output([linker, "--print-sysroot"], text=True).strip()
    runner = f"qemu-riscv64 -cpu max -L {sysroot} -E LD_LIBRARY_PATH=/lib:/lib64:/lib64/lp64d:/usr/lib:/usr/lib64"
    rv = campaign("riscv64gc-unknown-linux-gnu", f"-C target-feature=+zknh -C linker={linker}",
                  "riscv-scalar-crypto", runner)
    print("General SHA-512/t QEMU: PASS; all 510 parameters/4590 vectors, debug/release, both candidates")
    print("Production rejection and injected-KAT quarantine: PASS; not native admission")
    return arm, rv


if __name__ == "__main__":
    qemu()
