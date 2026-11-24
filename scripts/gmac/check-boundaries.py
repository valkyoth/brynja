"""Compare deterministic public GMAC boundary cases against Go's standard library."""
import hashlib
import os
from pathlib import Path
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "assurance/gmac-oracle/boundaries.go"
DIGEST = "92a98445cdc3aace66a724363bd6bd3e2ff1ec8f87a44fdb18627995015babc2"
EXPECTED = "generate=2730 verify=2730 reject=2730"


def main():
    invoke = runpy.run_path(str(ROOT / "scripts/gmac/check-consumer.py"))["invoke"]
    with tempfile.TemporaryDirectory(prefix="brynja-gmac-boundary-") as tmp:
        env = {"PATH": os.environ["PATH"], "HOME": tmp, "GOCACHE": str(Path(tmp) / "go-cache"),
               "GOENV": "off", "GOPROXY": "off", "GO111MODULE": "off",
               "CGO_ENABLED": "0", "GOTOOLCHAIN": "local"}
        oracle = subprocess.run(["go", "run", str(ORACLE)], cwd=tmp, env=env, check=True,
                                stdout=subprocess.PIPE, timeout=180)
        if hashlib.sha256(oracle.stdout).hexdigest() != DIGEST:
            raise ValueError("GMAC oracle transcript changed; review before accepting")
        data = oracle.stdout.decode("ascii")
        seal, valid, reject = data.split("\n", 3)[:3]
        wrong = (seal[:-1] + ("1" if seal[-1] == "0" else "0"),
                 valid.replace("open", "reject", 1), reject.replace("reject", "open", 1))
        for version in ("1.90.0", "1.100.0"):
            for route in ("direct", "facade"):
                def replay(rows):
                    return invoke(version, route, Path(tmp) / "target", "run",
                                  ["--release", "--example", "nist"], data=rows)
                result = replay(data)
                if result.returncode or result.stdout.strip() != EXPECTED:
                    raise RuntimeError(f"{version}/{route}: GMAC replay failed: " + result.stderr[-2000:])
                for row in wrong:
                    bad = replay(row + "\n")
                    if not bad.returncode or bad.stdout or "GMAC case 1 failed" not in bad.stderr:
                        raise ValueError("GMAC replay accepted an incorrect expected outcome")
                print(f"{version} {route}: {EXPECTED}", flush=True)
    print("GMAC_BOUNDARY_COMPLETE")


if __name__ == "__main__":
    main()
