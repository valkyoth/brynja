"""Isolated native timing execution and local source binding, not approval."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

import legacy_hmac_timing as timing

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "scripts/repository"))
import facade_cargo_environment as cargo_environment

FIXTURE = ROOT / "assurance/legacy-hmac-timing"
TOOLCHAIN = "1.99.1"
FEATURES = {"x86_64": {"sha1": "+sha,+sse2", "md5": "+avx2"},
            "aarch64": {"sha1": "+neon,+sha2", "md5": "+neon"}}


def environment(directory):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("CARGO_", "RUST", "BRYNJA_", "MIRI", "KANI", "ASAN_", "LSAN_", "UBSAN_"))}
    env["CARGO_HOME"] = os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))
    env["CARGO_TARGET_DIR"] = str(directory / "target")
    cargo_environment.check(ROOT, env)
    return env


def run(command, env, directory=ROOT):
    cargo_environment.check(directory, env)
    result = subprocess.run(command, env=env, cwd=directory, capture_output=True, text=True, timeout=300)
    if result.returncode:
        raise RuntimeError("legacy timing preparation failed: " + result.stdout[-3000:] + result.stderr[-3000:])
    return result.stdout


def architecture():
    return {"arm64": "aarch64"}.get(platform.machine(), platform.machine())


def prepare(route, family, directory, env):
    arch = architecture()
    timing.lanes(route, family, arch)
    if route.startswith("linux-") and sys.platform != "linux":
        raise ValueError("Linux timing requires Linux")
    if route.startswith("macos-") and sys.platform != "darwin":
        raise ValueError("resident timing requires macOS")
    result = dict(env)
    result["RUSTFLAGS"] = "-C target-cpu=generic"
    if route not in timing.COMPILED:
        return result, None
    probe = directory / "generic-host-probe"
    compile_command = ["rustc", "+" + TOOLCHAIN, "--edition=2024", "-C", "target-cpu=generic",
                       str(FIXTURE / "host_probe.rs"), "-o", str(probe)]
    run(compile_command, result)
    command = [str(probe), family]
    output = run(command, result)
    if output.splitlines() != ["LEGACY_HMAC_HOST_FEATURES: " + family]:
        raise ValueError("generic timing CPU preflight failed")
    result = {**result, "RUSTFLAGS": result["RUSTFLAGS"] + " -C target-feature=" + FEATURES[arch][family]}
    return result, {"compile_command": compile_command, "command": command, "output": output}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources(env):
    metadata = json.loads(run(["cargo", "+" + TOOLCHAIN, "metadata", "--format-version", "1",
                               "--locked", "--offline", "--manifest-path", str(FIXTURE / "Cargo.toml")], env))
    paths = {ROOT / "Cargo.toml", ROOT / "Cargo.lock", FIXTURE / "Cargo.lock", FIXTURE / "host_probe.rs"}
    for package in metadata["packages"]:
        manifest = Path(package["manifest_path"]).resolve()
        if package["source"] is not None or not manifest.is_relative_to(ROOT):
            raise ValueError("unexpected non-local timing dependency")
        paths.add(manifest)
        paths.update((manifest.parent / "src").rglob("*.rs"))
        if (manifest.parent / "build.rs").exists():
            paths.add(manifest.parent / "build.rs")
    for name in ("check-legacy-hmac-timing.py", "legacy_hmac_timing.py", "legacy_hmac_timing_runner.py"):
        paths.add(ROOT / "scripts/legacy-hmac" / name)
    paths.add(ROOT / "scripts/repository/facade_cargo_environment.py")
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def observe(route, family, destination):
    if destination.exists() or destination.is_symlink():
        raise ValueError("refusing to overwrite a timing observation")
    with cargo_environment.private_directory(ROOT) as raw:
        env, probe = prepare(route, family, Path(raw), environment(Path(raw)))
        before = sources(env)
        build = ["cargo", "+" + TOOLCHAIN, "build", "--release", "--locked", "--offline",
                 "--manifest-path", str(FIXTURE / "Cargo.toml")]
        run(build, env)
        binary = Path(env["CARGO_TARGET_DIR"]) / "release/brynja-legacy-hmac-timing"
        command = [str(binary), route, family]
        try:
            result = subprocess.run(command, env=env, cwd=ROOT, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired as error:
            def decoded(value):
                return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")
            result = subprocess.CompletedProcess(command, 124, decoded(error.stdout),
                                                 decoded(error.stderr) + "\ntiming deadline exceeded")
        failure, rows = None, []
        try:
            if result.returncode or result.stderr:
                raise ValueError("timing child failed or emitted diagnostics")
            rows = timing.parse(result.stdout, route, family, architecture())
            if sources(env) != before:
                raise ValueError("timing sources changed during collection")
        except ValueError as error:
            failure = str(error)
        compiler_path = Path(run(["rustup", "which", "--toolchain", TOOLCHAIN, "rustc"], env).strip())
        document = {
            "schema": 1, "kind": "author-operated-legacy-hmac-timing-observation",
            "claim": "diagnostic only; not constant-time proof, independent review or release qualification",
            "measurement_scope": "request key setup, digest/verification, output cleanup; hosted worker startup/join and compiled authority reconstruction included; session construction excluded",
            "route": route, "family": family, "host": platform.platform(), "machine": architecture(),
            "head": run(["git", "rev-parse", "HEAD"], env).strip(),
            "sources_sha256": before, "compiler": run(["rustc", "+" + TOOLCHAIN, "-vV"], env).strip(),
            "compiler_binary_sha256": digest(compiler_path), "binary_sha256": digest(binary),
            "build_command": build, "build_rustflags": env["RUSTFLAGS"], "generic_host_probe": probe,
            "command": command, "exit_status": result.returncode, "raw_stderr": result.stderr,
            "raw_output": result.stdout, "output_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            "failure": failure, "campaigns": rows, "signals": sum(row["signal"] for row in rows),
            "samples_per_class": timing.SAMPLES, "repetitions": timing.REPEAT, "alarm_threshold": timing.LIMIT,
        }
        with destination.open("x") as stream:
            json.dump(document, stream, indent=2, allow_nan=False)
            stream.write("\n")
    if failure:
        raise RuntimeError(failure + "; preserved observation=" + str(destination))
    if document["signals"]:
        raise RuntimeError("timing signal needs investigation; do not retry to hide it; observation=" + str(destination))
    return document
