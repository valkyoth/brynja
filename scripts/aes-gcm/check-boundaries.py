"""Offline Go-vs-Brynja portable AES-GCM boundary comparison on public data."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/repository"))
import facade_cargo_environment as workspace

FIXTURE = ROOT / "assurance/aes-gcm-consumer"
ORACLE = ROOT / "assurance/aes-gcm-oracle/boundaries.go"
TRANSCRIPT = "c7f322917ff1c24f0268cbb099fbbca3a0fd5d39da9380272d0623053c367f78"
EXPECTED = "seal=22050 open=22050 reject=22050"


def replay(toolchain, path, target):
    command = ["cargo", "+" + toolchain, "run", "--release", "--locked", "--offline",
               "--manifest-path", str(FIXTURE / "Cargo.toml"), "--no-default-features",
               "--features", "direct", "--example", "gcmvs", "--target-dir", str(target)]
    with path.open("rb") as stream:
        result = subprocess.run(command, cwd=ROOT, stdin=stream, text=True, capture_output=True, timeout=300)
    if result.returncode or result.stdout.strip() != EXPECTED:
        raise ValueError(f"{toolchain}: incomplete boundary replay: {result.stderr[-2000:]}")
    # Empty-message published fixture: each deliberately wrong expectation
    # must fail in the newly exercised buffer layout, not just alter a count.
    valid_tag = "58e2fccefa7e3061367f1d57a4e7455a"
    for kind in ("seal-in-place", "open-disjoint", "reject-disjoint"):
        tag = valid_tag if kind == "reject-disjoint" else "00" * 16
        row = "\t".join((kind, "00" * 16, "00" * 12, "", "", "", tag)) + "\n"
        bad = subprocess.run(command, cwd=ROOT, input=row, text=True, capture_output=True, timeout=60)
        if not bad.returncode or bad.stdout or "case 1: wrong result" not in bad.stderr:
            raise ValueError("boundary consumer did not detect a wrong expected outcome")
    print(f"{toolchain}: {EXPECTED}; 11025 messages, both layouts", flush=True)


def main():
    with workspace.private_directory(ROOT) as tmp:
        temp = Path(tmp)
        env = {"PATH": os.environ["PATH"], "HOME": str(temp), "GOENV": "off", "GOPROXY": "off",
               "GO111MODULE": "off", "GOTOOLCHAIN": "local", "CGO_ENABLED": "0",
               "GOCACHE": str(temp / "go-cache")}
        version = subprocess.check_output(["go", "version"], env=env, text=True, timeout=10)
        print(f"Independent host oracle: {version.strip()}", flush=True)
        path = temp / "public-vectors.tsv"
        with path.open("xb") as output:
            subprocess.run(["go", "run", str(ORACLE)], cwd=temp, env=env,
                           stdout=output, timeout=180, check=True)
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != TRANSCRIPT:
                raise ValueError("independent oracle transcript differs from reviewed inventory")
        for version in ("1.90.0", "1.100.0"):
            replay(version, path, temp / "cargo-target")
    print("AES_GCM_BOUNDARY_DIFFERENTIAL_COMPLETE")


if __name__ == "__main__":
    main()
