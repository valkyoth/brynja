"""Collect a new observation once, or analyse retained durations without executing AES."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
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

HERE = Path(__file__).resolve().parent
base = runpy.run_path(str(HERE / "check-paired-archives.py"))
ROOT, pkg, TARGET = (base[k] for k in ("ROOT", "pkg", "TARGET"))
VERSIONS = ("1.90.0", "1.100.0")
FIXTURE = ROOT / "assurance/aead-x86-timing/screen.rs"
PLAN = ROOT / "docs/assurance/aead-x86-timing-protocol.md"
RUN = ROOT / "assurance/aead-x86-observations/v0.29.3-amd"
CAMPAIGNS = [f"{w}-{o}-{c}" for w in (128, 192, 256)
             for o in ("seal", "open-reject", "generate", "verify-reject")
             for c in ("identical", "values")] + ["sensitivity"]
N = 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def statistics_for(a, b):
    differences = [x-y for x, y in zip(a, b, strict=True)]
    mean = statistics.mean(differences)
    def score(se):
        # None represents a nonzero constant difference (unbounded score).
        return mean / se if se else None if mean else 0.0
    return dict(delta_ns=mean, paired_t=score(statistics.stdev(differences)/math.sqrt(len(a))),
                welch_t=score(math.sqrt((statistics.variance(a)+statistics.variance(b))/len(a))))


def analyse(raw):
    lines = raw.decode("ascii").splitlines()
    if len(lines) != N * len(CAMPAIGNS):
        raise ValueError("incomplete or excess timing population")
    result = {}
    for j, name in enumerate(CAMPAIGNS):
        a, b, prev = [], [], None
        for i, line in enumerate(lines[j*N:(j+1)*N]):
            row = re.fullmatch(rf"{name} {i} ([01]) ([1-9][0-9]{{0,18}}) ([1-9][0-9]{{0,18}})", line)
            if not row or (i % 2 and row[1] == prev):
                raise ValueError("wrong campaign, duration, index or pair order")
            prev = row[1]
            a.append(int(row[2]))
            b.append(int(row[3]))
        stats = statistics_for(a, b)
        scores = [stats["paired_t"], stats["welch_t"]]
        if name == "sensitivity":
            ok = stats["delta_ns"] < 0 and all(s is None or s <= -4.5 for s in scores)
        else:
            ok = all(s is not None and abs(s) < 4.5 for s in scores)
        result[name] = dict(**stats, status="within-protocol" if ok else "flagged")
    return result


def collect(out):
    if (platform.system(), platform.machine()) != ("Linux", "x86_64") or any(k in os.environ for k in base["REJECT"]):
        raise ValueError("requires native Linux x86-64 without compiler or runner overrides")
    cpu = min(os.sched_getaffinity(0))
    fields = next(dict((k.strip(), v.strip()) for k, v in
                       (line.split(":", 1) for line in block.splitlines() if ":" in line))
                  for block in Path("/proc/cpuinfo").read_text().split("\n\n")
                  if re.search(rf"^processor\s*:\s*{cpu}$", block, re.M))
    if fields["model name"] != "AMD Ryzen 9 9950X3D 16-Core Processor" or not {
            "aes", "pclmulqdq", "sse2"} <= set(fields["flags"].split()):
        raise ValueError("declared host or ISA unavailable")
    # Build both images before measuring either. Compiler and setup failures
    # cannot be mistaken for a completed campaign.
    with pkg.cargo_environment.private_directory(ROOT) as tmp:
        root = Path(tmp)
        env = pkg.isolated_env(root)
        versions = pkg.package_archives(root, pkg.MODERN, VERSIONS[-1], env)
        consumer = root / "consumer"
        (consumer / "examples").mkdir(parents=True)
        shutil.copyfile(FIXTURE, consumer / "examples/screen.rs")
        (consumer / "Cargo.toml").write_text(
            '[workspace]\n[package]\nname="paired-screen"\nversion="0.0.0"\nedition="2024"\npublish=false\n'
            f'[dependencies.brynja-crypto]\nversion="={versions["brynja-crypto"]}"\ndefault-features=false\n'
            'features=["aes-gcm-execution","gmac-execution"]\n[patch.crates-io]\n' +
            "".join(f'{n}={{path="../unpacked/{n}-{v}"}}\n' for n, v in versions.items()))
        pkg.run(["cargo", "+" + VERSIONS[0], "generate-lockfile", "--offline"], consumer, env)
        flags = "-Ctarget-feature=+aes,+sse2"
        env.update(RUSTFLAGS=flags)
        builds = {}
        for version in VERSIONS:
            cargo = ["cargo", "+" + version]
            meta = json.loads(pkg.run(cargo + ["metadata", "--format-version=1", "--locked", "--offline"],
                                      consumer, env).stdout)
            artifact = pkg.run(cargo + ["build", "--locked", "--offline", "--release", "--target", TARGET,
                                        "--example", "screen", "--message-format=json"], consumer, env)
            image = base["executable"](artifact.stdout, meta["resolve"]["root"], "screen",
                                       root / "target" / TARGET / "release/examples/screen")
            shutil.copy2(image, root / version)
            builds[version] = dict(compiler=pkg.run(["rustc", "+" + version, "-vV"], consumer, env).stdout,
                                   elf_sha256=digest(image.read_bytes()))
        out.mkdir(parents=True, exist_ok=False)
        info = dict(cpu=cpu, model=fields["model name"], microcode=fields.get("microcode"), kernel=platform.release(),
                    started=datetime.now(timezone.utc).isoformat(), target=TARGET, flags=flags,
                    protocol=digest(PLAN.read_bytes()), fixture=digest(FIXTURE.read_bytes()), builds=builds,
                    runner=digest(Path(__file__).read_bytes()),
                    packages={n: digest((root / f"target/package/{n}-{v}.crate").read_bytes())
                              for n, v in versions.items()})
        (out / "build.json").write_text(json.dumps(info, indent=2)+"\n")
        os.sched_setaffinity(0, {cpu})
        for version in VERSIONS:
            image = root / version
            if digest(image.read_bytes()) != builds[version]["elf_sha256"]:
                raise ValueError("changed timing executable")
            with (out / (version+".txt.gz")).open("xb") as file, gzip.GzipFile(fileobj=file, mode="wb", mtime=0) as gz:
                # Keep partial stdout even on failure, never a success record.
                try:
                    result = subprocess.run([str(image)], env=env, cwd=consumer, capture_output=True, timeout=180)
                except subprocess.TimeoutExpired as exc:
                    gz.write(exc.stdout or b"")
                    raise
                gz.write(result.stdout)
            if result.returncode:
                raise ValueError(f"{version}: timing executable failed ({result.returncode})")
            record = dict(raw_sha256=digest(result.stdout), results=analyse(result.stdout))
            (out / (version+".json")).write_text(json.dumps(record, indent=2, allow_nan=False)+"\n")


def replay(out):
    build = json.loads((out / "build.json").read_text())
    if build["protocol"] != digest(PLAN.read_bytes()) or build["fixture"] != digest(FIXTURE.read_bytes()):
        raise ValueError("record belongs to another protocol or fixture")
    flagged = False
    for v in VERSIONS:
        raw = gzip.decompress((out / (v+".txt.gz")).read_bytes())
        summary = analyse(raw)
        if dict(raw_sha256=digest(raw), results=summary) != json.loads((out / (v+".json")).read_text()):
            raise ValueError("retained results do not match raw samples")
        flags = [k for k, s in summary.items() if s["status"] == "flagged"]
        print(f"{v}: {len(summary)} campaigns; flagged: {', '.join(flags) or 'none'}")
        flagged |= bool(flags)
    return flagged


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("collect", "replay"))
    parser.add_argument("--output", type=Path, default=RUN)
    args = parser.parse_args()
    if args.mode == "collect":
        collect(args.output)
    flagged = replay(args.output)
    print("AEAD_TIMING_RECORDS_REPLAYED")
    if flagged and args.mode == "collect":
        raise SystemExit("Timing alarm or control failure retained; do not repeat to pass")
