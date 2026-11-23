"""Build, measure once per named host, or replay the bounded GHASH timing screen."""
import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import re
import runpy
import shutil
import subprocess
import tempfile

BASE = runpy.run_path(str(Path(__file__).with_name("check-portable-host.py")))
ROOT, VERSIONS = BASE["ROOT"], BASE["COMPILERS"]
digest, summarize = BASE["digest"], BASE["summarize"]
FIXTURE = ROOT / "assurance/ghash-timing"
TARGET = "x86_64-unknown-linux-gnu"
FLAGS = "--cfg brynja_ghash_pclmul_evidence"
HOSTS = {"amd": ("AuthenticAMD", "AMD Ryzen 9 9950X3D 16-Core Processor"),
         "intel": ("GenuineIntel", "Intel(R) Xeon(R) 6975P-C"),
         "aws": (None, "Neoverse-V2"), "apple": (None, "Apple M2 Pro"),
         "x60": (None, "spacemit,x60")}


def configuration(host):
    if host == "x60":
        return ("riscv64gc-unknown-linux-gnu", "-C target-feature=+crt-static --cfg brynja_ghash_rv64_evidence",
                "rv64-screen", TARGET)
    if host in ("amd", "intel"):
        return TARGET, FLAGS, "pclmul-screen", TARGET
    target = {"aws": "aarch64-unknown-linux-musl", "apple": "aarch64-apple-darwin"}[host]
    return target, "--cfg brynja_ghash_pmull_evidence", "pmull-screen", target if host == "apple" else TARGET


def prepare(bundle, host="amd", source_base=None, binary="brynja-ghash-timing"):
    from hmac_verifiers import environment
    import tomllib
    bundle.mkdir(exist_ok=False)
    files = [FIXTURE / p for p in ("Cargo.toml", "Cargo.lock", "src/main.rs")]
    if binary == "pmull-order":
        files.extend([FIXTURE / "src/bin/pmull-order.rs", ROOT / "scripts/ghash/check-pmull-order.py",
                      ROOT / "docs/assurance/ghash-pmull-order-control.md"])
    if binary in ("rv64-branches", "amd-counters", "aws-counters"):
        files.extend([FIXTURE / f"src/bin/{binary}.rs", FIXTURE / "src/counter_window.rs",
                      ROOT / "scripts/ghash/check-rv64-branches.py"])
    if binary == "amd-counters":
        files.extend([ROOT / "scripts/ghash/check-amd-counters.py", ROOT / "scripts/ghash/ghash-user-counters.c"])
    if binary == "aws-counters":
        files.append(ROOT / "scripts/ghash/check-aws-counters.py")
    for package in tomllib.loads((FIXTURE / "Cargo.lock").read_text())["package"]:
        if package["name"] != "brynja-ghash-timing":
            crate = ROOT / "crates" / package["name"]
            files.extend([crate / "Cargo.toml", *sorted((crate / "src").rglob("*.rs"))])
    files.extend([ROOT / "Cargo.toml", Path(__file__).resolve(), Path(__file__).with_name("check-portable-host.py").resolve(),
                  ROOT / "scripts/hmac/hmac_verifiers.py", ROOT / "scripts/repository/facade_cargo_environment.py"])
    target, flags, feature, compiler_host = configuration(host)
    if binary == "aws-counters":
        feature = "aws-counter-window"
    head = source_base or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if not re.fullmatch("[0-9a-f]{40}", head):
        raise ValueError("invalid source base")
    manifest = dict(target=target, rustflags=flags, feature=feature, base_commit=head,
                    sources={str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in sorted(files)}, builds={})
    if binary != "brynja-ghash-timing":
        manifest["binary"] = binary
    if host == "x60":
        linker = shutil.which("riscv64-linux-gnu-gcc") or shutil.which("riscv64-suse-linux-gcc")
        if not linker:
            raise ValueError("requires a RISC-V GNU cross linker")
        manifest["linker_version"] = subprocess.check_output([linker, "--version"], text=True).splitlines()[0]
    with tempfile.TemporaryDirectory() as tmp:
        for ver in VERSIONS:
            env = environment(Path(tmp) / ver)
            env.update(RUSTUP_AUTO_INSTALL="0", RUSTFLAGS=flags)
            if host == "aws":
                env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"] = "rust-lld"
            elif host == "x60":
                env["CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER"] = linker
            compiler = subprocess.check_output(["rustc", "+" + ver, "-vV"], env=env, text=True)
            if "host: " + compiler_host not in compiler.splitlines():
                raise ValueError("unexpected build compiler host")
            subprocess.run(["cargo", "+" + ver, "build", "--target", target, "--release", "--locked", "--offline",
                            "--features", feature, "--bin", binary, "--manifest-path", str(FIXTURE / "Cargo.toml")],
                           check=True, cwd=ROOT, env=env, timeout=300)
            exe = bundle / ver
            shutil.copy2(Path(env["CARGO_TARGET_DIR"]) / target / "release" / binary, exe)
            manifest["builds"][ver] = dict(compiler=compiler, binary_sha256=digest(exe.read_bytes()))
    (bundle / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")


def build_info(directory, host="amd", binary="brynja-ghash-timing"):
    data = (directory / "build.json").read_bytes()
    info = json.loads(data)
    if info.get("binary", "brynja-ghash-timing") != binary:
        raise ValueError("wrong measurement executable")
    target, flags, feature, compiler_host = configuration(host)
    if binary == "aws-counters":
        feature = "aws-counter-window"
    if (info["target"], info["rustflags"], info["feature"]) != (target, flags, feature):
        raise ValueError("unexpected build configuration")
    for ver in VERSIONS:
        b = info["builds"][ver]
        if (not b["compiler"].startswith("rustc " + ver + " ") or "host: " + compiler_host not in b["compiler"].splitlines()
                or not re.fullmatch(r"[a-f0-9]{64}", b["binary_sha256"])):
            raise ValueError("unexpected build identity")
    return info["builds"], digest(data)


def require_x60(fields):
    if fields.get("uarch") != HOSTS["x60"][1] or "zbc" not in fields.get("isa", "").split("_"):
        raise ValueError("requires SpacemiT X60 with scalar Zbc on the pinned CPU")


def placement(host):
    if host == "apple":
        if ((platform.system(), platform.machine()) != ("Darwin", "arm64")
                or subprocess.check_output(["sysctl", "-n", "hw.optional.arm.FEAT_PMULL"], text=True).strip() != "1"
                or subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip() != HOSTS[host][1]):
            raise ValueError("requires native M2 Pro with PMULL")
        return None
    arch = {"aws": "aarch64", "x60": "riscv64"}.get(host, "x86_64")
    if (platform.system(), platform.machine()) != ("Linux", arch):
        raise ValueError("requires matching native Linux host")
    cpu = min(os.sched_getaffinity(0))
    block = next(b for b in Path("/proc/cpuinfo").read_text().split("\n\n")
                 if re.search(rf"^processor\s*:\s*{cpu}$", b, re.M))
    fields = dict((k.strip(), v.strip()) for k, v in (line.split(":", 1) for line in block.splitlines() if ":" in line))
    if host == "x60":
        require_x60(fields)
    elif host == "aws":
        info = subprocess.check_output(["lscpu"], text=True, env=dict(os.environ, LC_ALL="C"))
        if ("pmull" not in fields["Features"].split() or
                not re.search(r"^Model name:\s*Neoverse-V2\s*$", info, re.M)):
            raise ValueError("requires Neoverse-V2 with PMULL")
    elif ((fields["vendor_id"], fields["model name"]) != HOSTS[host]
            or not {"pclmulqdq", "sse2"} <= set(fields["flags"].split())):
        raise ValueError("pinned CPU does not match the declared host and instructions")
    return cpu


def measure(bundle, host, dest):
    cpu = placement(host)
    prefix = [] if cpu is None else ["taskset", "-c", str(cpu)]
    builds, build_hash = build_info(bundle, host)
    for ver in VERSIONS:
        if digest((bundle / ver).read_bytes()) != builds[ver]["binary_sha256"]:
            raise ValueError("benchmark binary mismatch")
    dest.mkdir(exist_ok=False)
    shutil.copy2(bundle / "build.json", dest / "build.json")
    for ver in VERSIONS:
        path = dest / f"{ver}.txt"
        with path.open("xb") as raw:
            subprocess.run([*prefix, str((bundle / ver).resolve())], stdout=raw, check=True, timeout=180)
        data = path.read_bytes()
        record = dict(host=host, model=HOSTS[host][1], cpu=cpu, os=platform.platform(),
                      utc=datetime.now(timezone.utc).isoformat(), build_sha256=build_hash,
                      binary_sha256=builds[ver]["binary_sha256"], raw_sha256=digest(data), results=summarize(data))
        if host == "x60":
            record["required_scalar_extension"] = "zbc"
        (dest / f"{ver}.json").write_text(json.dumps(record, indent=2) + "\n")


def replay(host, dest):
    builds, build_hash = build_info(dest, host)
    alarms = []
    for ver in VERSIONS:
        record = json.loads((dest / f"{ver}.json").read_text())
        raw = (dest / f"{ver}.txt").read_bytes()
        cpu = record["cpu"]
        placed = cpu is None if host == "apple" else type(cpu) is int and cpu >= 0
        if host == "x60" and (record.get("required_scalar_extension") != "zbc"
                              or not record["os"].startswith("Linux-") or "riscv64" not in record["os"]):
            raise ValueError("unexpected X60 execution record")
        if (record["host"] != host or record["model"] != HOSTS[host][1] or not placed
                or record["build_sha256"] != build_hash
                or record["binary_sha256"] != builds[ver]["binary_sha256"] or record["raw_sha256"] != digest(raw)):
            raise ValueError("record identity mismatch")
        results = summarize(raw)
        for mode, actual in results.items():
            saved = record["results"][mode]
            if actual["alarm"] is not saved["alarm"]:
                raise ValueError("alarm mismatch")
            for metric in ("mean_difference_ns", "paired_t"):
                a, b = actual[metric], saved[metric]
                if not (a is b is None or a is not None and b is not None and math.isclose(a, b, abs_tol=1e-10)):
                    raise ValueError("statistic mismatch")
            if actual["alarm"]:
                alarms.append((ver, mode))
        print(host, ver, json.dumps(results))
    return alarms


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("bundle", type=Path)
    prep.add_argument("--host", choices=HOSTS, default="amd")
    prep.add_argument("--source-base", help="base commit for an exported working tree")
    for name in ("measure", "replay"):
        sub = commands.add_parser(name)
        if name == "measure":
            sub.add_argument("bundle", type=Path)
        sub.add_argument("host", choices=HOSTS)
        sub.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.bundle, args.host, args.source_base)
    else:
        if args.command == "measure":
            measure(args.bundle, args.host, args.directory)
        alarms = replay(args.host, args.directory)
        print("Retained alarms:", alarms)
        if args.command == "measure" and alarms:
            raise SystemExit("Investigate separately; do not retry to pass")
