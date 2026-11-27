"""Collect or replay the bounded Linux x86-64 end-to-end GHASH throughput comparison."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/hmac"))

FIXTURE = ROOT / "assurance/ghash-throughput"
VERSIONS = ("1.90.0", "1.100.0")
CASES = ((16, 16, 4096), (1024, 1024, 128), (16384, 16384, 8), (16384, 13, 8))
ROUTES = ("portable", "candidate")
PAIRS = 12


def digest(data):
    return hashlib.sha256(data).hexdigest()


def order(pair):
    return ROUTES if pair % 2 == 0 else ROUTES[::-1]


def summarize(raw):
    lines = raw.decode("ascii").splitlines()
    if len(lines) != PAIRS * 2 * len(CASES):
        raise ValueError("incomplete or excessive throughput population")
    rows = iter(lines)
    samples = {case: {r: [] for r in ROUTES} for case in CASES}
    for pair in range(PAIRS):
        for route in order(pair):
            for size, chunk, count in CASES:
                prefix = f"{pair} {route} {size} {chunk} {count} "
                match = re.fullmatch(prefix + r"([1-9][0-9]{0,18})", next(rows))
                if not match:
                    raise ValueError("unexpected order, route, workload or duration")
                samples[size, chunk, count][route].append(int(match[1]) / count)
    summary = {}
    for (size, chunk, _), routes in samples.items():
        med = {r: statistics.median(values) for r, values in routes.items()}
        summary[f"{size}/{chunk}"] = dict(portable_ns=med["portable"], candidate_ns=med["candidate"],
                                          speedup=med["portable"] / med["candidate"])
    return summary


def collect(output):
    from hmac_verifiers import environment
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        raise ValueError("this collection protocol requires native x86_64 Linux")
    output.mkdir(parents=True, exist_ok=False)
    cpu = min(os.sched_getaffinity(0))
    cpuinfo = Path("/proc/cpuinfo").read_text().split("\n\n")
    block = next(b for b in cpuinfo if re.search(rf"^processor\s*:\s*{cpu}$", b, re.M))
    model = re.search(r"^model name\s*:\s*(.+)$", block, re.M)[1]
    sources = [FIXTURE / p for p in ("Cargo.toml", "Cargo.lock", "src/main.rs")]
    sources += [ROOT / p for p in ("Cargo.toml", "crates/brynja-crypto/src/ghash.rs",
                "crates/brynja-universal-hash-ghash/src/ghash.rs", "crates/brynja-universal-hash-ghash/src/ghash/field.rs", "crates/brynja-crypto-cpu/src/ghash_pclmul.rs",
                "crates/brynja-crypto-cpu/src/ghash_admission.rs", "scripts/ghash/check-throughput.py")]
    inputs = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in sources}
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory() as tmp:
        for version in VERSIONS:
            bins = {}
            for route in ROUTES:
                env = environment(Path(tmp) / version / route)
                env["RUSTUP_AUTO_INSTALL"] = "0"
                if route == "candidate":
                    env["RUSTFLAGS"] = "--cfg brynja_ghash_pclmul_evidence"
                    env["BRYNJA_GHASH_EVIDENCE"] = "1"
                compiler = subprocess.check_output(["rustc", "+" + version, "-vV"], env=env, text=True)
                if "host: x86_64-unknown-linux-gnu" not in compiler:
                    raise ValueError("wrong compiler host")
                subprocess.run(["cargo", "+" + version, "build", "--manifest-path",
                                str(FIXTURE / "Cargo.toml"), "--locked", "--offline", "--release"],
                               env=env, cwd=ROOT, check=True, timeout=300)
                bins[route] = Path(env["CARGO_TARGET_DIR"]) / "release/brynja-ghash-throughput"
            hashes = {r: digest(p.read_bytes()) for r, p in bins.items()}
            data = measure_batches(output, version, cpu, bins, env)
            record = dict(compiler=compiler, host=platform.platform(), model=model, cpu=cpu,
                          utc=datetime.now(timezone.utc).isoformat(), base_commit=head,
                          source_sha256=inputs, binary_sha256=hashes, raw_sha256=digest(data),
                          results=summarize(data))
            (output / f"{version}.json").write_text(json.dumps(record, indent=2) + "\n")


def measure_batches(output, version, cpu, bins, env):
    prefix = [] if cpu is None else ["taskset", "-c", str(cpu)]
    raw_path = output / f"{version}.txt"
    with raw_path.open("xb") as raw:
        for pair in range(PAIRS):
            for route in order(pair):
                result = subprocess.check_output([*prefix, str(bins[route])],
                                                 env=env, timeout=60)
                for line in result.splitlines():
                    raw.write(str(pair).encode() + b" " + line + b"\n")
                raw.flush()
    return raw_path.read_bytes()


def replay(output):
    for version in VERSIONS:
        data = (output / f"{version}.txt").read_bytes()
        record = json.loads((output / f"{version}.json").read_text())
        if (record["raw_sha256"] != digest(data) or record["results"] != summarize(data)
                or not record["compiler"].startswith("rustc " + version + " ")
                or set(record["binary_sha256"]) != set(ROUTES)
                or len(set(record["binary_sha256"].values())) != 2
                or not all(re.fullmatch("[0-9a-f]{64}", h) for h in record["binary_sha256"].values())):
            raise ValueError(f"inconsistent throughput record: {version}")
        print(version, json.dumps(record["results"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("collect", "replay"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.mode == "collect":
        collect(args.directory)
    replay(args.directory)
    print("GHASH_THROUGHPUT_" + args.mode.upper() + "_COMPLETE")
