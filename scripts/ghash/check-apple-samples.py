"""Measure or replay process-attributed M2 event samples, not per-kernel counts."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import xml.etree.ElementTree as ET

EVENTS = ("INST_BRANCH", "L1D_CACHE_MISS_LD")
VERSIONS = ("1.90.0", "1.100.0")
PERIOD = 65536
MANIFEST = "0447684582c093e8976b23094b16ef01175d37222ddb51fed9d5fd2ca9053ca8"
OPTIONS = {"configurationType": {"manual": {}}, "countingLevel": "EL0",
           "sampleByTime": False, "pmiThreshold": PERIOD, "allEventsAndFormulas": []}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hashes(bundle):
    path = bundle / "build.json"
    if digest(path) != MANIFEST:
        raise ValueError("not the retained Apple throughput build")
    return {v: json.loads(path.read_bytes())["builds"][v]["binary_sha256"]["candidate"]
            for v in VERSIONS}


def checked_rows(toc, rows, event, exe):
    run, = toc.findall("run")
    target, = run.findall("info/target/process")
    if (target.get("type"), target.get("name"), target.get("return-exit-status"),
        target.get("termination-reason")) != ("launched", exe.name, "0", "exit(0)"):
        raise ValueError("target missing, changed or incomplete")
    pid = int(target.attrib["pid"])
    p, = [p for p in run.findall("processes/process") if p.get("pid") == str(pid)]
    if Path(p.attrib["path"]).resolve() != exe.resolve():
        raise ValueError("wrong executable in trace")
    table, = run.findall("data/table[@schema='counters-profile']")
    if (table.get("pmi-event"), table.get("pmi-threshold"), table.get("target-pid"),
        table.get("trigger")) != (json.dumps(event), str(PERIOD), "SINGLE", "pmi"):
        raise ValueError("counter configuration mismatch")
    node, = rows.findall("node")
    cols = [c.findtext("mnemonic") for c in node.findall("schema/col")]
    if any(cols.count(name) != 1 for name in ("process", "weight", "time")):
        raise ValueError("incomplete or ambiguous sample schema")
    ids = {e.attrib["id"]: e for e in node.iter() if "id" in e.attrib}

    def resolve(elem):
        return ids[elem.attrib["ref"]] if "ref" in elem.attrib else elem

    selected = []
    for row in node.findall("row"):
        proc = resolve(row[cols.index("process")])
        if proc.tag == "sentinel":
            continue
        if proc.tag != "process":
            raise ValueError("unknown process field")
        if int(resolve(proc.find("pid")).text) != pid:
            continue
        weight = resolve(row[cols.index("weight")])
        if weight.tag != "pmc-event" or int(weight.text) != PERIOD:
            raise ValueError("unexpected target sample weight")
        selected.append(int(resolve(row[cols.index("time")]).text))
    return selected


def measure(bundle, dest):
    pins = hashes(bundle)
    model = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
    if (model, platform.system(), platform.machine()) != ("Apple M2 Pro", "Darwin", "arm64"):
        raise ValueError("requires the native M2 Pro")
    for v in VERSIONS:
        if digest(bundle / (v + "-candidate")) != pins[v]:
            raise ValueError("binary mismatch")
    dest.mkdir(exist_ok=False)
    base = ["xcrun", "xctrace", "record", "--no-prompt", "--instrument", "CPU Counters"]
    for event in EVENTS:
        cfg = json.loads(subprocess.check_output(base + ["--show-recording-options"]))
        cfg["CPU Counters"].update(OPTIONS, pmiEventAliasOrMnemonic=event)
        opt = dest / (event + ".json")
        opt.write_text(json.dumps(cfg))
        for v in VERSIONS:
            exe = (bundle / (v + "-candidate")).resolve()
            trace = dest / f"{v}-{event}.trace"
            subprocess.run(base + ["--recording-options", str(opt), "--output", str(trace),
                                   "--time-limit", "30s", "--launch", "--", str(exe)],
                           check=True, timeout=90)
            export = ["xcrun", "xctrace", "export", str(trace)]
            toc = ET.fromstring(subprocess.check_output(export + ["--toc"], timeout=60))
            rows = ET.fromstring(subprocess.check_output(export + [
                "--xpath", "/trace-toc/run[1]/data/table[@schema='counters-profile']"], timeout=60))
            times = checked_rows(toc, rows, event, exe)
            rec = dict(model=model, version=v, binary_sha256=pins[v], event=event, period=PERIOD,
                       options=cfg["CPU Counters"], tool=toc.findtext("run/info/summary/instruments-version"),
                       started=toc.findtext("run/info/summary/start-date"), sample_times_ns=times)
            (dest / f"{v}-{event}.samples.json").write_text(json.dumps(rec, indent=2) + "\n")
            print(v, event, len(times), "target samples", flush=True)


def replay(bundle, dest):
    pins = hashes(bundle)
    for event in EVENTS:
        for v in VERSIONS:
            rec = json.loads((dest / f"{v}-{event}.samples.json").read_bytes())
            if (rec["model"], rec["version"], rec["event"], rec["period"], rec["binary_sha256"]) != (
                    "Apple M2 Pro", v, event, PERIOD, pins[v]):
                raise ValueError("inconsistent sampling record")
            for k, value in dict(OPTIONS, pmiEventAliasOrMnemonic=event).items():
                if rec["options"][k] != value:
                    raise ValueError("different recording options")
            times = rec["sample_times_ns"]
            if not isinstance(times, list) or any(type(t) is not int or t < 0 for t in times):
                raise ValueError("invalid relative timestamps")
            print(v, event, len(times), "target samples")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["measure", "replay"])
    parser.add_argument("bundle", type=Path)
    parser.add_argument("dest", type=Path)
    args = parser.parse_args()
    (measure if args.mode == "measure" else replay)(args.bundle, args.dest)
