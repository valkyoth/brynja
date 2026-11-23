"""Optional AWS observation. Only the OS perf collector is elevated; never the fixture."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import runpy
import select
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
R = runpy.run_path(str(HERE / "check-rv64-branches.py"))
C = R["C"]
BRANCH = R["EVENTS"]
GENERIC = (*BRANCH, "cache-references:u", "cache-misses:u")
L1 = (*BRANCH, "L1-dcache-loads:u", "L1-dcache-load-misses:u")
ARM = tuple("armv8_pmuv3_0/" + e + "/u" for e in ("br_retired", "br_mis_pred_retired", "l1d_cache", "l1d_cache_refill"))
PROFILES = {"generic": GENERIC, "branches": BRANCH, "intel-l1": L1, "arm-pmu": ARM,
            "arm-l1-only": ARM[2:]}
SELECTED = {"aws": ("branches", "arm-l1-only"), "intel": ("intel-l1",)}
BIN = "aws-counters"


def collector(pid, events):
    if type(pid) is not int or pid <= 1 or events not in PROFILES.values():
        raise ValueError("requires a single child PID and fixed event group")
    return ["/usr/bin/sudo", "-n", "-H", "--", "/usr/bin/perf", "stat", "--no-inherit",
            "--no-big-num", "-x", ";", "-e", "{" + ",".join(events) + "}", "-p", str(pid),
            "-D", "-1", "--control", "fd:0,1", "--timeout", "5000"]


def expect(stream, expected):
    if not select.select([stream], [], [], 8)[0]:
        raise ValueError("counter handshake timed out")
    # Both writers use one short pipe write and wait for our acknowledgement.
    actual = os.read(stream.fileno(), 128)
    if actual.rstrip(b"\0") != expected:
        raise ValueError(f"expected {expected!r}, got {actual!r}")


def window(cmd, marker, events):
    uid = os.getuid()
    if not uid or uid != os.geteuid():
        raise ValueError("run the driver and workload as a normal user")
    child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    perf = None
    try:
        expect(child.stdout, b"enable\n")
        # The still-live child is blocked on our pipe, not a PID supplied by the caller.
        status = Path(f"/proc/{child.pid}/status").read_text()
        ids = re.search(r"^Uid:\s+(.+)$", status, re.M)
        if (not ids or list(map(int, ids[1].split())) != [uid] * 4
                or not re.search(r"^CapEff:\s+0+$", status, re.M)):
            raise ValueError("fixture credentials mismatch")
        perf = subprocess.Popen(collector(child.pid, events), cwd="/", env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        try:
            for command in (b"enable\n", b"disable\n"):
                if command.startswith(b"d"):
                    expect(child.stdout, command)
                perf.stdin.write(command)
                expect(perf.stdout, b"ack\n")
                child.stdin.write(b"ack\n")
            expect(child.stdout, marker + b"\n")
            if child.wait(timeout=5):
                raise ValueError("fixture failed")
            _, err = perf.communicate(timeout=8)
        except (ValueError, BrokenPipeError) as exc:
            _, err = perf.communicate(timeout=8)
            raise ValueError(f"{exc}: {err.decode()[-600:]}") from exc
        if perf.returncode:
            raise ValueError("counter collector failed: " + err.decode()[-600:])
        return err.decode()
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        if perf is not None and perf.poll() is None:
            perf.communicate(timeout=8)


def synthetic():
    data = bytearray(16 * 1024 * 1024)
    print("enable", flush=True)
    assert input() == "ack"
    for i in range(len(data) // 64):
        data[(i * 65537 * 64) % len(data)] = i % 251
    print("disable", flush=True)
    assert input() == "ack"
    print("positive control completed", flush=True)


def counts(report, events):
    lines = [line.split(";") for line in report.splitlines() if ";" in line]
    if len(lines) != len(events):
        raise ValueError("incomplete counter group")
    vals = []
    for row, event in zip(lines, events, strict=True):
        if (len(row) < 5 or row[1:3] != ["", event] or not re.fullmatch(r"[0-9]+", row[0])
                or not re.fullmatch(r"[1-9][0-9]*", row[3]) or row[4] != "100.00"):
            raise ValueError(f"missing, mislabeled or multiplexed counter: {event}")
        vals.append(int(row[0]))
    if events[:2] in (BRANCH, ARM[:2]) and vals[1] > vals[0]:
        raise ValueError("branch misses exceed branches")
    return vals


def positive(cpu, events):
    raw = window(["taskset", "-c", str(cpu), sys.executable, str(Path(__file__).resolve()), "synthetic"],
                 b"positive control completed", events)
    print(raw, end="", flush=True)
    if not all(counts(raw, events)):
        raise ValueError("positive control did not exercise all requested counters")
    return raw


def summary(data, events):
    return R["summary"](data, lambda report: counts(report, events), events, envelope=True)


def selected(host, profile):
    if profile not in SELECTED[host]:
        raise ValueError("not a declared measurement group for this host")
    return PROFILES[profile]


def measure(bundle, host, profile, dest):
    events = selected(host, profile)
    cpu = C["placement"](host)
    builds, bh = C["build_info"](bundle, host, BIN)
    for ver in R["VERSIONS"]:
        if C["digest"]((bundle / ver).read_bytes()) != builds[ver]["binary_sha256"]:
            raise ValueError("fixture digest mismatch")
    dest.mkdir(exist_ok=False)
    shutil.copyfile(bundle / "build.json", dest / "build.json")
    raw_probe = positive(cpu, events)
    (dest / "probe.txt").write_text(raw_probe)
    for ver in R["VERSIONS"]:
        path = dest / f"{ver}.jsonl"
        with path.open("x") as out:
            for mode, pair, label in R["schedule"]():
                marker = f"completed {0 if mode == 'empty' else 4096} native blocks".encode()
                raw = window(["taskset", "-c", str(cpu), str((bundle / ver).resolve()), mode,
                              str(label), str(pair), "/dev/stdout", "/dev/stdin"], marker, events)
                out.write(json.dumps(dict(launch=[mode, pair, label], perf=raw)) + "\n")
                out.flush()
                counts(raw, events)
        data = path.read_bytes()
        rec = dict(host=host, profile=profile, model=C["HOSTS"][host][1], cpu=cpu, os=platform.platform(),
                   uid=os.getuid(), perf=subprocess.check_output(["/usr/bin/perf", "version"], text=True).strip(),
                   utc=datetime.now(timezone.utc).isoformat(), raw_sha256=C["digest"](data),
                   build_sha256=bh, binary_sha256=builds[ver]["binary_sha256"],
                   probe_sha256=C["digest"](raw_probe.encode()), results=summary(data, events))
        (dest / f"{ver}.json").write_text(json.dumps(rec, indent=2) + "\n")


def replay(host, profile, dest):
    builds, bh = C["build_info"](dest, host, BIN)
    probe = (dest / "probe.txt").read_bytes()
    events = selected(host, profile)
    if not all(counts(probe.decode(), events)):
        raise ValueError("missing positive control")
    alarms = []
    for ver in R["VERSIONS"]:
        raw = (dest / f"{ver}.jsonl").read_bytes()
        rec = json.loads((dest / f"{ver}.json").read_text())
        result = summary(raw, events)
        if (rec["host"] != host or rec["profile"] != profile or rec["model"] != C["HOSTS"][host][1] or rec["uid"] <= 0 or rec["cpu"] < 0
                or rec["build_sha256"] != bh or rec["binary_sha256"] != builds[ver]["binary_sha256"]
                or rec["probe_sha256"] != C["digest"](probe) or rec["raw_sha256"] != C["digest"](raw)
                or rec["results"] != result):
            raise ValueError("inconsistent AWS counter record")
        alarms.extend((ver, mode, event) for mode, events in result["campaigns"].items()
                      for event, stat in events.items() if stat["alarm"])
    return alarms


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    subs = p.add_subparsers(dest="mode", required=True)
    subs.add_parser("synthetic")
    for mode in ("probe", "prepare", "measure", "replay"):
        sub = subs.add_parser(mode)
        sub.add_argument("host", choices=("aws", "intel"))
        if mode in ("probe", "measure", "replay"):
            sub.add_argument("profile", choices=PROFILES)
        if mode in ("prepare", "measure"):
            sub.add_argument("bundle", type=Path)
        if mode in ("measure", "replay"):
            sub.add_argument("dest", type=Path)
    a = p.parse_args()
    if a.mode == "synthetic":
        synthetic()
    elif a.mode == "probe":
        positive(C["placement"](a.host), PROFILES[a.profile])
    elif a.mode == "prepare":
        C["prepare"](a.bundle, a.host, binary=BIN)
    else:
        if a.mode == "measure":
            measure(a.bundle, a.host, a.profile, a.dest)
        alarms = replay(a.host, a.profile, a.dest)
        print("Retained alarms:", alarms)
        if a.mode == "measure" and alarms:
            raise SystemExit("Alarm retained; do not retry to pass")
