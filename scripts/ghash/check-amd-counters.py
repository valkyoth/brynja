"""Prepare, collect once, or replay the AMD GHASH user-mode counter observation."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import re
import runpy
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
R = runpy.run_path(str(HERE / "check-rv64-branches.py"))
C = R["C"]
BIN = "amd-counters"
SOURCE = "scripts/ghash/ghash-user-counters.c"
EVENTS = (*R["EVENTS"], "cache-references:u", "cache-misses:u")
FLAGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]


def digest(path):
    return C["digest"](path.read_bytes())


def save(path, record):
    with path.open("x") as out:
        json.dump(record, out, indent=2)
        out.write("\n")


def prepare(bundle):
    C["prepare"](bundle, "amd", binary=BIN)
    source = HERE / Path(SOURCE).name
    subprocess.run(["cc", *FLAGS, str(source), "-o", str(bundle / "counter")], check=True)
    save(bundle / "driver.json", dict(cc=subprocess.check_output(["cc", "--version"], text=True).splitlines()[0],
         flags=FLAGS, source_sha256=digest(source), binary_sha256=digest(bundle / "counter")))


def metadata(directory):
    builds, bh = C["build_info"](directory, "amd", BIN)
    driver = json.loads((directory / "driver.json").read_text())
    manifest = json.loads((directory / "build.json").read_text())
    if (driver["flags"] != FLAGS or not driver["cc"] or not re.fullmatch("[a-f0-9]{64}", driver["binary_sha256"])
            or driver["source_sha256"] != manifest["sources"][SOURCE]):
        raise ValueError("inconsistent counter driver identity")
    return builds, bh, driver


def counts(line):
    if not re.fullmatch(r"[0-9]{1,20}( [0-9]{1,20}){5}\n?", line):
        raise ValueError("missing or malformed group")
    enabled, running, *values = map(int, line.split())
    if enabled == 0 or enabled != running or values[1] > values[0]:
        raise ValueError("inconsistent or multiplexed group")
    return values


def probe(report):
    if not all(counts(report)):
        raise ValueError("positive control did not exercise every event")


def summary(data):
    return R["summary"](data, counts, EVENTS, envelope=True)


def measure(bundle, dest):
    builds, bh, driver = metadata(bundle)
    cpu = C["placement"]("amd")
    if digest(bundle / "counter") != driver["binary_sha256"] or any(
            digest(bundle / ver) != builds[ver]["binary_sha256"] for ver in R["VERSIONS"]):
        raise ValueError("binary identity mismatch")
    dest.mkdir(exist_ok=False)
    for name in ("build.json", "driver.json"):
        shutil.copy2(bundle / name, dest / name)
    cmd = ["taskset", "-c", str(cpu), str((bundle / "counter").resolve())]
    result = subprocess.check_output([*cmd, "probe"], text=True, timeout=30)
    (dest / "probe.txt").write_text(result)
    probe(result)
    for ver in R["VERSIONS"]:
        raw = dest / f"{ver}.jsonl"
        with raw.open("x") as out:
            for mode, pair, label in R["schedule"]():
                run = subprocess.run([*cmd, str((bundle / ver).resolve()), mode, str(label), str(pair)],
                                     text=True, capture_output=True, timeout=30)
                out.write(json.dumps(dict(launch=[mode, pair, label], perf=run.stdout)) + "\n")
                out.flush()
                if run.returncode:
                    raise ValueError(f"counter window failed: {run.stderr[-300:]}")
                counts(run.stdout)
        save(dest / f"{ver}.json", dict(target=C["HOSTS"]["amd"][1], cpu=cpu, os=platform.platform(),
             utc=datetime.now(timezone.utc).isoformat(), raw_sha256=digest(raw), build_sha256=bh,
             binary_sha256=builds[ver]["binary_sha256"], driver_sha256=digest(dest / "driver.json"),
             probe_sha256=digest(dest / "probe.txt"), results=summary(raw.read_bytes())))


def replay(dest):
    builds, bh, _ = metadata(dest)
    probe((dest / "probe.txt").read_text())
    alarms = []
    for ver in R["VERSIONS"]:
        raw = dest / f"{ver}.jsonl"
        rec = json.loads((dest / f"{ver}.json").read_text())
        results = summary(raw.read_bytes())
        if (type(rec["cpu"]) is not int or rec["cpu"] < 0 or rec["target"] != C["HOSTS"]["amd"][1]
                or rec["build_sha256"] != bh or rec["binary_sha256"] != builds[ver]["binary_sha256"]
                or rec["raw_sha256"] != digest(raw) or rec["driver_sha256"] != digest(dest / "driver.json")
                or rec["probe_sha256"] != digest(dest / "probe.txt") or results != rec["results"]):
            raise ValueError("inconsistent observation")
        alarms.extend((ver, mode, event) for mode, items in results["campaigns"].items()
                      for event, stat in items.items() if stat["alarm"])
    return alarms


if __name__ == "__main__":
    subs = argparse.ArgumentParser(description=__doc__)
    parser = subs.add_subparsers(dest="mode", required=True)
    parser.add_parser("prepare").add_argument("bundle", type=Path)
    collect = parser.add_parser("measure")
    collect.add_argument("bundle", type=Path)
    collect.add_argument("dest", type=Path)
    parser.add_parser("replay").add_argument("dest", type=Path)
    args = subs.parse_args()
    if args.mode == "prepare":
        prepare(args.bundle)
    else:
        if args.mode == "measure":
            measure(args.bundle, args.dest)
        alarms = replay(args.dest)
        print("Retained alarms:", alarms)
        if alarms and args.mode == "measure":
            raise SystemExit("Alarm retained; do not retry to pass")
