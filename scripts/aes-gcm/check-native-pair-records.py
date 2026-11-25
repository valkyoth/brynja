"""Validate retained v0.29.3 functional observations; never contact a builder."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2] / "assurance/aead-native-observations/v0.29.3"
HOSTS = {"linux-arm64": ("aarch64-unknown-linux-gnu", "+aes,+neon"),
         "macos-arm64": ("aarch64-apple-darwin", "+aes,+neon"),
         "windows-x64": ("x86_64-pc-windows-msvc", "+aes,+sse2")}
VERSIONS = ("1.90.0", "1.100.0")
INPUTS = "056ea67a077239f798bbbab35864177bb607e421f1cf260d163a72394b81bfff"
CASES = {"aes-gcm-go": "seal=22050 open=22050 reject=22050",
         "aes-gcm-nist": "seal=16875 open=8371 reject=8504",
         "gmac-go": "generate=2730 verify=2730 reject=2730",
         "gmac-nist": "generate=3375 verify=1657 reject=1718"}
ROUTES = ("direct", "facade")


def validate(record, host, version):
    target, isa = HOSTS[host]
    compiler = record["compiler"].splitlines()
    if (record["host"] != host or not record["os"] or record["specialized"] != isa
            or record["inputs_sha256"] != INPUTS
            or f"host: {target}" not in compiler or f"release: {version}" not in compiler):
        raise ValueError("wrong native host, compiler or input manifest")
    if record["tests"] != {"absence": 1, "required": 3, "field": 1, "lifecycle": 3, "interruptions": 9}:
        raise ValueError("missing native test population")
    if record["replay"] != {f"{r}/{k}.tsv": v for r in ROUTES for k, v in CASES.items()}:
        raise ValueError("wrong direct/facade replay population")
    images = record["images"]
    if (set(images) != {f"{r}/{f}" for r in ROUTES for f in ("aes-gcm", "gmac")}
            or any(not re.fullmatch("[0-9a-f]{64}", h) for h in images.values())):
        raise ValueError("missing native executable identity")


def check(root=ROOT):
    if hashlib.sha256((root / "inputs.json").read_bytes()).hexdigest() != INPUTS:
        raise ValueError("native input manifest digest mismatch")
    lines = []
    for host in sorted(HOSTS):
        for version in sorted(VERSIONS):
            name = f"{host}/{version}.json"
            data = (root / name).read_bytes()
            validate(json.loads(data), host, version)
            lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    if (root / "SHA256SUMS").read_text().splitlines() != lines:
        raise ValueError("native observation digest mismatch")


if __name__ == "__main__":
    check()
    print("AEAD_NATIVE_PAIR_RECORDS_COMPLETE")
