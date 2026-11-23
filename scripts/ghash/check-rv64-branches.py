"""Collect or replay process-local user-mode counters for the forced X60 GHASH update."""
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
import statistics
import subprocess
import tempfile

C = runpy.run_path(str(Path(__file__).with_name("check-pclmul-screen.py")))
VERSIONS = C["VERSIONS"]
EVENTS = ("branches:u", "branch-misses:u")
L1 = ("L1-dcache-loads", "L1-dcache-load-misses")
MODES = ("identical", "subkey", "block")
PAIRS = 16
BIN = "rv64-branches"


def schedule():
    yield "empty", 0, 0
    for mode in MODES:
        for pair in range(PAIRS):
            for label in ((0, 1) if pair % 2 == 0 else (1, 0)):
                yield mode, pair, label
    yield "empty", 1, 0


def counts(report, events=EVENTS):
    lines = [s.split(";") for s in report.splitlines() if s.strip() and not s.startswith("#")]
    if len(lines) != len(events):
        raise ValueError("incomplete or extra counter report")
    values = []
    for row, event in zip(lines, events, strict=True):
        if (len(row) < 5 or row[1:3] != ["", event] or not re.fullmatch(r"[0-9]+", row[0])
                or not re.fullmatch(r"[1-9][0-9]*", row[3]) or row[4] != "100.00"):
            raise ValueError("counter missing, multiplexed or mislabeled")
        values.append(int(row[0]))
    if values[1] > values[0]:
        raise ValueError("misses exceed total")
    if events == L1 and lines[0][3] != lines[1][3]:
        raise ValueError("inconsistent L1 group running times")
    return values


def summary(raw, parse=counts, events=EVENTS, *, envelope=False):
    rows = [json.loads(line) for line in raw.splitlines()]
    expected = list(schedule())
    if len(expected) != len(rows):
        raise ValueError("incomplete or extra launches")
    empty = []
    active = {mode: {0: [], 1: []} for mode in MODES}
    for (mode, pair, label), row in zip(expected, rows, strict=True):
        if [mode, pair, label] != row["launch"]:
            raise ValueError("unexpected launch order")
        vals = parse(row["perf"])
        if mode == "empty":
            empty.append(vals)
        else:
            active[mode][label].append(vals)
    if min(v[0] for mode in active.values() for label in mode.values() for v in label) <= max(v[0] for v in empty):
        raise ValueError("active window does not exceed empty branch envelope")
    results = {}
    for mode, labels in active.items():
        results[mode] = {}
        for i, event in enumerate(events):
            a, b = ([r[i] for r in labels[c]] for c in (0, 1))
            diffs = [x-y for x, y in zip(a, b, strict=True)]
            mean, sd = statistics.mean(diffs), statistics.stdev(diffs)
            t = mean / (sd / math.sqrt(PAIRS)) if sd else (0 if mean == 0 else None)
            results[mode][event] = dict(medians=[statistics.median(a), statistics.median(b)],
                                        mean_difference=mean, paired_t=t, alarm=t is None or abs(t) >= 4.5)
            if envelope:
                results[mode][event]["all_active_above_empty"] = min(a + b) > max(v[i] for v in empty)
    return dict(empty=empty, campaigns=results)


def l1_control(report):
    blocks = re.findall(r"^perf_event_attr:\n(.*?)(?=^-{5})", report, re.M | re.S)
    if len(blocks) != 2:
        raise ValueError("missing L1 event attributes")
    for block, config in zip(blocks, ("0", "0x10000"), strict=True):
        for key, value in (("type", "3"), ("config", config), ("exclude_hv", "1"), ("exclude_kernel", "1")):
            if not re.search(rf"^  {key}\s+{value}(?: |$)", block, re.M):
                raise ValueError("unverified cache event or privilege filter")
    csv = "\n".join(line for line in report.splitlines() if ";" in line)
    if not all(counts(csv, L1)):
        raise ValueError("L1 positive control did not count both events")


def measure(bundle, dest, *, l1=False):
    builds, bh = C["build_info"](bundle, "x60", BIN)
    cpu = C["placement"]("x60")
    for ver in VERSIONS:
        if C["digest"]((bundle / ver).read_bytes()) != builds[ver]["binary_sha256"]:
            raise ValueError("executable mismatch")
    dest.mkdir(exist_ok=False)
    shutil.copy2(bundle / "build.json", dest / "build.json")
    perf = subprocess.check_output(["perf", "version"], text=True).strip()
    labels = L1 if l1 else EVENTS
    group = "{" + ",".join(s + ":u" if l1 else s for s in labels) + "}"
    parse = lambda report: counts(report, labels)
    if l1:
        if os.geteuid() == 0:
            raise ValueError("unprivileged X60 measurement required")
        ctrl = subprocess.run(["taskset", "-c", str(cpu), "perf", "stat", "-vv", "--no-inherit",
                               "--no-big-num", "-x", ";", "-e", group, "--", "python3", "-c",
                               "print(sum(bytearray(4*1024*1024)[::64]))"],
                              text=True, capture_output=True, timeout=30, env=dict(os.environ, LC_ALL="C"))
        # Retain the event attributes and raw CSV; omit transient task and fd numbers.
        blocks = re.findall(r"^perf_event_attr:\n.*?^-{5,}$", ctrl.stderr, re.M | re.S)
        csv = [line for line in ctrl.stderr.splitlines() if ";" in line]
        control = "\n".join(blocks + csv) + "\n"
        (dest / "positive.txt").write_text(control)
        ctrl.check_returncode()
        l1_control(control)
    for ver in VERSIONS:
        raw = dest / f"{ver}.jsonl"
        with raw.open("x") as out, tempfile.TemporaryDirectory() as tmp:
            ctl, ack = [Path(tmp) / s for s in ("ctl", "ack")]
            for fifo in (ctl, ack):
                os.mkfifo(fifo, 0o600)
            for n, (mode, pair, label) in enumerate(schedule()):
                log = Path(tmp) / f"{n}.csv"
                cmd = ["taskset", "-c", str(cpu), "perf", "stat", "--no-big-num", "-x", ";",
                       *(["--no-inherit"] if l1 else []), "-e", group, "-D", "-1", "--control", f"fifo:{ctl},{ack}",
                       "-o", str(log), "--", str((bundle / ver).resolve()), mode, str(label), str(pair),
                       str(ctl), str(ack)]
                res = subprocess.run(cmd, timeout=30, capture_output=True, text=True, env=dict(os.environ, LC_ALL="C"))
                report = log.read_text() if log.exists() else ""
                out.write(json.dumps(dict(launch=[mode, pair, label], perf=report)) + "\n")
                out.flush()
                expected = 0 if mode == "empty" else 4096
                if res.returncode or res.stdout.strip() != f"completed {expected} native blocks":
                    raise ValueError(f"counter launch {n} failed: {res.stderr[-600:]}")
                parse(report)
        data = raw.read_bytes()
        record = dict(target="spacemit,x60", cpu=cpu, host=platform.platform(), perf=perf,
                      utc=datetime.now(timezone.utc).isoformat(), raw_sha256=C["digest"](data),
                      build_sha256=bh, binary_sha256=builds[ver]["binary_sha256"],
                      results=summary(data, parse, labels, envelope=l1))
        if l1:
            record.update(profile="l1-data-loads", control_sha256=C["digest"](control.encode()),
                          collector_sha256=C["digest"](Path(__file__).read_bytes()))
        (dest / f"{ver}.json").write_text(json.dumps(record, indent=2) + "\n")


def replay(dest, *, l1=False):
    builds, bh = C["build_info"](dest, "x60", BIN)
    alarms = []
    for ver in VERSIONS:
        raw = (dest / f"{ver}.jsonl").read_bytes()
        rec = json.loads((dest / f"{ver}.json").read_text())
        if l1:
            control = (dest / "positive.txt").read_bytes()
            l1_control(control.decode())
            if rec["profile"] != "l1-data-loads" or rec["control_sha256"] != C["digest"](control):
                raise ValueError("inconsistent L1 observation")
        labels = L1 if l1 else EVENTS
        results = summary(raw, lambda report: counts(report, labels), labels, envelope=l1)
        if (type(rec["cpu"]) is not int or rec["cpu"] < 0 or rec["target"] != "spacemit,x60"
                or rec["build_sha256"] != bh or rec["raw_sha256"] != C["digest"](raw)
                or rec["binary_sha256"] != builds[ver]["binary_sha256"] or results != rec["results"]):
            raise ValueError("inconsistent branch observation")
        alarms += [(ver, mode, event) for mode, events in results["campaigns"].items()
                   for event, result in events.items() if result["alarm"]]
        print(ver, json.dumps(results))
    return alarms


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="mode", required=True)
    subs.add_parser("prepare").add_argument("bundle", type=Path)
    collect = subs.add_parser("measure")
    collect.add_argument("bundle", type=Path)
    collect.add_argument("dest", type=Path)
    collect.add_argument("--l1", action="store_true")
    replay_parser = subs.add_parser("replay")
    replay_parser.add_argument("dest", type=Path)
    replay_parser.add_argument("--l1", action="store_true")
    args = parser.parse_args()
    if args.mode == "prepare":
        C["prepare"](args.bundle, "x60", binary=BIN)
    else:
        if args.mode == "measure":
            measure(args.bundle, args.dest, l1=args.l1)
        alarms = replay(args.dest, l1=args.l1)
        print("Retained alarms:", alarms)
        if alarms and args.mode == "measure":
            raise SystemExit("Alarm retained; do not retry to pass")
