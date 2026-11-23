"""Prepare, measure or replay the named-host GHASH throughput comparisons."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

SPEC = importlib.util.spec_from_file_location("throughput", Path(__file__).with_name("check-throughput.py"))
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
TARGET = "aarch64-unknown-linux-musl"
APPLE = "aarch64-apple-darwin"
FLAG = "--cfg brynja_ghash_pmull_evidence"
RV64 = "riscv64gc-unknown-linux-gnu"
INTEL = "x86_64-unknown-linux-gnu"
STATIC = "-C target-feature=+crt-static"


def flags(target, route):
    if target == INTEL:
        return "--cfg brynja_ghash_pclmul_evidence" if route == "candidate" else ""
    if target == RV64:
        return STATIC + (" --cfg brynja_ghash_rv64_evidence" if route == "candidate" else "")
    return FLAG if route == "candidate" else ""


def valid_target(manifest, target):
    return (manifest["target"] == target and manifest["candidate_rustflags"] == flags(target, "candidate")
            and (target not in (RV64, INTEL) or manifest.get("portable_rustflags") == flags(target, "portable")))


def prepare(bundle, target=TARGET, source_base=None):
    from hmac_verifiers import environment
    import tomllib
    if target == APPLE and (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise ValueError("Apple benchmarks must be compiled natively")
    bundle.mkdir(exist_ok=False)
    sources = [B.FIXTURE / name for name in ("Cargo.toml", "Cargo.lock", "src/main.rs")]
    packages = tomllib.loads((B.FIXTURE / "Cargo.lock").read_text())["package"]
    for crate in (pkg["name"] for pkg in packages if pkg["name"] != "brynja-ghash-throughput"):
        root = B.ROOT / "crates" / crate
        sources += [root / "Cargo.toml", *sorted((root / "src").rglob("*.rs"))]
    sources += [B.ROOT / "Cargo.toml", Path(__file__).resolve(), Path(B.__file__),
                B.ROOT / "scripts/hmac/hmac_verifiers.py", B.ROOT / "scripts/repository/facade_cargo_environment.py"]
    inputs = {str(p.relative_to(B.ROOT)): B.digest(p.read_bytes()) for p in sorted(sources)}
    head = source_base or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=B.ROOT, text=True).strip()
    if not re.fullmatch("[0-9a-f]{40}", head):
        raise ValueError("invalid source base for exported working tree")
    manifest = dict(target=target, candidate_rustflags=flags(target, "candidate"), base_commit=head,
                    source_sha256=inputs, builds={})
    if target == INTEL:
        manifest["portable_rustflags"] = ""
    if target == RV64:
        linker = shutil.which("riscv64-linux-gnu-gcc") or shutil.which("riscv64-suse-linux-gcc")
        if not linker:
            raise ValueError("RV64 GNU cross linker required")
        manifest.update(portable_rustflags=STATIC,
                        linker_version=subprocess.check_output([linker, "--version"], text=True).splitlines()[0])
    with tempfile.TemporaryDirectory() as tmp:
        for version in B.VERSIONS:
            hashes = {}
            for route in B.ROUTES:
                env = environment(Path(tmp) / version / route)
                env["RUSTUP_AUTO_INSTALL"] = "0"
                if target == TARGET:
                    env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"] = "rust-lld"
                elif target == RV64:
                    env["CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER"] = linker
                if flags(target, route):
                    env["RUSTFLAGS"] = flags(target, route)
                compiler = subprocess.check_output(["rustc", "+" + version, "-vV"], text=True, env=env)
                if target == APPLE and "host: " + APPLE not in compiler.splitlines():
                    raise ValueError("wrong native compiler host")
                subprocess.run(["cargo", "+" + version, "build", "--target", target, "--locked",
                                "--offline", "--release", "--manifest-path", str(B.FIXTURE / "Cargo.toml")],
                               cwd=B.ROOT, env=env, check=True, timeout=300)
                exe = bundle / f"{version}-{route}"
                shutil.copy2(Path(env["CARGO_TARGET_DIR"]) / target / "release/brynja-ghash-throughput", exe)
                hashes[route] = B.digest(exe.read_bytes())
            manifest["builds"][version] = dict(compiler=compiler, binary_sha256=hashes)
    (bundle / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")


def checked_builds(bundle, manifest, target=TARGET):
    if not valid_target(manifest, target):
        raise ValueError("unexpected build target or candidate flags")
    builds = {}
    for version in B.VERSIONS:
        meta = manifest["builds"][version]
        bins = {route: bundle.resolve() / f"{version}-{route}" for route in B.ROUTES}
        hashes = {route: B.digest(p.read_bytes()) for route, p in bins.items()}
        if (hashes != meta["binary_sha256"] or len(set(hashes.values())) != 2
                or not meta["compiler"].startswith("rustc " + version + " ")):
            raise ValueError("benchmark binary or compiler mismatch")
        builds[version] = bins
    return builds


def scalar_extensions(isa):
    found = sorted(set(isa.split("_")) & {"zbc", "zbkc"})
    if not found:
        raise ValueError("pinned RV64 CPU lacks scalar Zbc/Zbkc")
    return found


def intel_cpu(block):
    fields = dict((k.strip(), v.strip()) for k, v in (line.split(":", 1) for line in block.splitlines() if ":" in line))
    if fields.get("vendor_id") != "GenuineIntel" or "pclmulqdq" not in fields.get("flags", "").split():
        raise ValueError("pinned CPU must be Intel with PCLMULQDQ")
    return fields["model name"], dict(vendor=fields["vendor_id"], pclmulqdq=True)


def placement(target):
    if target == APPLE:
        if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
            raise ValueError("measure requires native Apple silicon")
        if subprocess.check_output(["sysctl", "-n", "hw.optional.arm.FEAT_PMULL"], text=True).strip() != "1":
            raise ValueError("Apple CPU lacks PMULL")
        return None, subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip(), {}
    arch = {RV64: "riscv64", TARGET: "aarch64", INTEL: "x86_64"}[target]
    if (platform.system(), platform.machine()) != ("Linux", arch):
        raise ValueError(f"measure requires native {arch} Linux")
    cpu = min(os.sched_getaffinity(0))
    block = next(b for b in Path("/proc/cpuinfo").read_text().split("\n\n")
                 if re.search(rf"^processor\s*:\s*{cpu}$", b, re.M))
    if target == INTEL:
        model, extra = intel_cpu(block)
        return cpu, model, extra
    if target == RV64:
        isa = re.search(r"^isa\s*:\s*(\S+)$", block, re.M)[1]
        model = re.search(r"^uarch\s*:\s*(.+)$", block, re.M)[1]
        return cpu, model, dict(isa=isa, scalar_extensions=scalar_extensions(isa))
    if "pmull" not in re.search(r"^Features\s*:(.+)$", block, re.M)[1].split():
        raise ValueError("pinned CPU lacks PMULL")
    info = subprocess.check_output(["lscpu"], text=True, env=dict(os.environ, LC_ALL="C"))
    model = re.search(r"^Model name:\s*(.+)$", info, re.M)[1]
    return cpu, model, {}


def measure(bundle, output, target=TARGET):
    cpu, model, extra = placement(target)
    manifest = json.loads((bundle / "build.json").read_text())
    builds = checked_builds(bundle, manifest, target)
    output.mkdir(exist_ok=False)
    # Keep the common build provenance once, not once per sample or compiler.
    shutil.copyfile(bundle / "build.json", output / "build.json")
    for version, bins in builds.items():
        raw = B.measure_batches(output, version, cpu, bins, None)
        record = dict(**manifest["builds"][version], target=target, base_commit=manifest["base_commit"],
                      host=platform.platform(), model=model, cpu=cpu, utc=datetime.now(timezone.utc).isoformat(),
                      build_sha256=B.digest((output / "build.json").read_bytes()),
                      raw_sha256=B.digest(raw), results=B.summarize(raw), **extra)
        (output / f"{version}.json").write_text(json.dumps(record, indent=2) + "\n")


def replay(output, target=TARGET):
    data = (output / "build.json").read_bytes()
    manifest = json.loads(data)
    if not valid_target(manifest, target):
        family = {RV64: "RV64", INTEL: "Intel"}.get(target, "ARM")
        raise ValueError(f"unexpected {family} build provenance")
    for version in B.VERSIONS:
        record = json.loads((output / f"{version}.json").read_text())
        if target == INTEL and (type(record["cpu"]) is not int or record["cpu"] < 0
                                or not record["host"].startswith("Linux-") or "x86_64" not in record["host"]
                                or record["vendor"] != "GenuineIntel" or record["pclmulqdq"] is not True):
            raise ValueError("unexpected Intel host, CPU placement or PCLMUL capability")
        if target == RV64 and (type(record["cpu"]) is not int or record["cpu"] < 0
                               or not record["host"].startswith("Linux-") or "riscv64" not in record["host"]
                               or record["scalar_extensions"] != scalar_extensions(record["isa"])):
            raise ValueError("unexpected RV64 host, CPU placement or scalar capability")
        if target == APPLE and (record["cpu"] is not None or "host: " + APPLE not in record["compiler"].splitlines()
                                or not record["host"].startswith("macOS-") or "arm64" not in record["host"]):
            raise ValueError("unexpected Apple compiler, host or CPU placement")
        if (record["build_sha256"] != B.digest(data) or record["target"] != target
                or record["base_commit"] != manifest["base_commit"]
                or any(record[k] != manifest["builds"][version][k] for k in ("binary_sha256", "compiler"))):
            raise ValueError("inconsistent build provenance")
    B.replay(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    targets = parser.add_mutually_exclusive_group()
    targets.add_argument("--apple", action="store_true", help="use native macOS arm64, without CPU pinning")
    targets.add_argument("--rv64", action="store_true", help="use native Linux RV64 scalar Zbc/Zbkc")
    targets.add_argument("--intel", action="store_true", help="use native Intel Linux PCLMULQDQ")
    commands = parser.add_subparsers(dest="mode", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("bundle", type=Path)
    prep.add_argument("--source-base", help="base commit of an exported development working tree without .git")
    collect = commands.add_parser("measure")
    collect.add_argument("bundle", type=Path)
    collect.add_argument("output", type=Path)
    commands.add_parser("replay").add_argument("output", type=Path)
    args = parser.parse_args()
    target = INTEL if args.intel else RV64 if args.rv64 else APPLE if args.apple else TARGET
    if args.mode == "prepare":
        prepare(args.bundle, target, args.source_base)
    else:
        if args.mode == "measure":
            measure(args.bundle, args.output, target)
        replay(args.output, target)
    family = {RV64: "RV64", INTEL: "INTEL"}.get(target, "ARM")
    print(f"GHASH_{family}_THROUGHPUT_{args.mode.upper()}_COMPLETE")
