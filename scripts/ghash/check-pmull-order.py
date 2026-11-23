"""One-shot Neoverse-V2 order diagnostic; replay never collects measurements."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import re
import runpy
import shutil
import statistics
import subprocess

C = runpy.run_path(str(Path(__file__).with_name("check-pclmul-screen.py")))
VERSIONS = C["VERSIONS"]


def analyze(raw):
    rows = raw.splitlines()
    if len(rows) != 6144:
        raise ValueError("incomplete timing population")
    normalized, first_effects = [], {}
    for index, mode in enumerate(("identical", "subkey", "block")):
        strata = [[], []]
        for i in range(0, 2048, 4):
            labels = []
            for j in range(4):
                m = re.fullmatch(rb"(\w+) ([01]) ([1-9]\d{0,18}) ([1-9]\d{0,18})",
                                 rows[2048 * index + i + j])
                if not m or m[1] != mode.encode():
                    raise ValueError("invalid mode or sample")
                first, a, b = map(int, m.groups()[1:])
                labels.append(first)
                strata[j % 2].append((a-b) if first == 0 else (b-a))
                normalized.append(b" ".join((m[1], m[3], m[4])))
            if labels[0] == labels[2] or labels[1] == labels[3]:
                raise ValueError("order confounded with parity")
        first_effects[mode] = [statistics.mean(s) for s in strata]
    return dict(label=C["summarize"](b"\n".join(normalized)), first_minus_second_ns=first_effects)


def measure(bundle, dest):
    cpu = C["placement"]("aws")
    builds, build_hash = C["build_info"](bundle, "aws", "pmull-order")
    for v in VERSIONS:
        if C["digest"]((bundle / v).read_bytes()) != builds[v]["binary_sha256"]:
            raise ValueError("binary digest mismatch")
    dest.mkdir(exist_ok=False)
    shutil.copy2(bundle / "build.json", dest / "build.json")
    for v in VERSIONS:
        raw = dest / (v + ".txt")
        with raw.open("xb") as stream:
            subprocess.run(["taskset", "-c", str(cpu), str((bundle / v).resolve())],
                           stdout=stream, check=True, timeout=180)
        data = raw.read_bytes()
        record = dict(model="Neoverse-V2", cpu=cpu, os=platform.platform(),
                      utc=datetime.now(timezone.utc).isoformat(), build_sha256=build_hash,
                      raw_sha256=C["digest"](data), binary_sha256=builds[v]["binary_sha256"],
                      analysis=analyze(data))
        (dest / (v + ".json")).write_text(json.dumps(record, indent=2) + "\n")


def replay(dest):
    builds, build_hash = C["build_info"](dest, "aws", "pmull-order")
    alarms = []
    for v in VERSIONS:
        raw = (dest / (v + ".txt")).read_bytes()
        r = json.loads((dest / (v + ".json")).read_bytes())
        a = analyze(raw)
        if (r["model"] != "Neoverse-V2" or type(r["cpu"]) is not int or r["cpu"] < 0
                or not r["os"].startswith("Linux-") or "aarch64" not in r["os"]
                or (build_hash, builds[v]["binary_sha256"], C["digest"](raw), a) !=
                   (r["build_sha256"], r["binary_sha256"], r["raw_sha256"], r["analysis"])):
            raise ValueError("order-control record mismatch")
        alarms.extend((v, k) for k, m in a["label"].items() if m["alarm"])
        print(v, json.dumps(a))
    return alarms


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("prepare").add_argument("bundle", type=Path)
    m = sub.add_parser("measure")
    m.add_argument("bundle", type=Path)
    m.add_argument("results", type=Path)
    sub.add_parser("replay").add_argument("results", type=Path)
    args = p.parse_args()
    if args.action == "prepare":
        C["prepare"](args.bundle, "aws", binary="pmull-order")
    else:
        if args.action == "measure":
            measure(args.bundle, args.results)
        alarms = replay(args.results)
        print("Retained order-control alarms:", alarms)
        if args.action == "measure" and alarms:
            raise SystemExit("Alarm retained; do not retry to pass")
