"""Offline downstream GMAC checks. No registry package, device or network needed."""
import argparse
from collections import Counter
from pathlib import Path
import runpy
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "assurance/gmac-consumer/Cargo.toml"
EXPECTED = {"seal": 3375, "open": 1657, "reject": 1718}


def select_gmac(rows):
    """GCMVS has no separate GMAC file. Empty PT alone also matches failed decrypts
    with nonempty CT; require *both* text fields to be empty."""
    for row in rows:
        op, key, iv, aad, ct, pt, tag = row.split("\t")
        if not ct and not pt:
            yield "\t".join((op, key, iv, aad, tag))


def corpus():
    # The existing parser validates the SHA-256, archive members, all parameter
    # groups, field lengths and counts before it returns any admitted records.
    source = runpy.run_path(str(ROOT / "scripts/aes-gcm/check-gcmvs.py"))
    rows = list(select_gmac(source["corpus"](source["ARCHIVE"]).splitlines()))
    if Counter(row.partition("\t")[0] for row in rows) != EXPECTED:
        raise ValueError("incomplete GMAC inventory")
    return rows


def invoke(version, route, target, action, flags, *, data=None):
    return subprocess.run(
        ["cargo", "+" + version, action, "--locked", "--offline", "--manifest-path", MANIFEST,
         "--no-default-features", "--features", route, "--target-dir", target, *flags],
        cwd=ROOT, input=data, capture_output=True, text=True, timeout=240)


def public(version, route, target):
    for action, flags, marker in (
            ("test", ["--release", "--lib"], "1 passed; 0 failed; 0 ignored;"),
            ("test", ["--doc"], "4 passed; 0 failed; 0 ignored;"),
            ("check", ["--lib", "--target", "thumbv7em-none-eabi"], None)):
        run = invoke(version, route, target, action, flags)
        if run.returncode or (marker and marker not in run.stdout):
            raise RuntimeError(f"{version}/{route}: {action} {flags} failed: " + run.stderr[-2000:])
    print(f"{version} {route}: public GMAC, feature isolation, typed tag, Cortex-M compile", flush=True)


def nist(version, route, target, rows):
    def replay(data):
        return invoke(version, route, target, "run", ["--release", "--example", "nist"], data=data)

    result = replay("\n".join(rows) + "\n")
    expected = "generate=3375 verify=1657 reject=1718"
    if result.returncode or result.stdout.strip() != expected:
        raise RuntimeError(f"{version}/{route}: incomplete GMAC replay: " + result.stderr[-2000:])
    # A count-only or always-success verifier must not pass these controls.
    seal = next(row for row in rows if row.startswith("seal\t"))
    wrong_tag = seal[:-1] + ("0" if seal[-1] != "0" else "1")
    reject = next(row for row in rows if row.startswith("reject\t"))
    for control in (wrong_tag, reject.replace("reject", "open", 1)):
        bad = replay(control + "\n")
        if not bad.returncode or bad.stdout or "GMAC case 1 failed" not in bad.stderr:
            raise RuntimeError("GMAC negative control did not fail as expected")
    print(f"{version} {route}: {expected}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", choices=("public", "nist"))
    campaign = parser.parse_args().campaign
    rows = corpus() if campaign == "nist" else None
    with tempfile.TemporaryDirectory(prefix="brynja-gmac-") as target:
        for version in ("1.90.0", "1.100.0"):
            for route in ("direct", "facade"):
                if rows is None:
                    public(version, route, target)
                else:
                    nist(version, route, target, rows)
    print(f"GMAC_{campaign.upper()}_COMPLETE")


if __name__ == "__main__":
    main()
