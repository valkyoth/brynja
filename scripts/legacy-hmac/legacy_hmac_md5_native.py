#!/usr/bin/env python3
"""Explicit native MD5 HMAC SIMD; author testing, not release qualification."""
import hashlib
import hmac
import os
from pathlib import Path
import platform
import subprocess

from legacy_hmac_acceptance import require
import legacy_hmac_bits
import legacy_hmac_md5_lanes

ROOT = Path(__file__).resolve().parents[2]
MARKERS = (
    "LEGACY_MD5_BATCH: 256 masks, 70 byte cases, 88 bit cases; no fallback",
    "LEGACY_MD5_BATCH_LIFECYCLE: all tag bytes checked; preflight before work; three profiles budget/revocation",
    "LEGACY_MD5_BATCH_FAILURES: scalar/SIMD normalization; public/secret/verify; every cancel/revoke/unwind boundary",
    "LEGACY_MD5_BATCH_LANES: 96 batches, 768 distinct-lane records; 7 tag widths; public/secret/verify",
)


def features():
    architecture, system = platform.machine().lower(), platform.system()
    if system == "Linux":
        sets = [set(value.split()) for line in Path("/proc/cpuinfo").read_text().splitlines()
                for key, separator, value in [line.partition(":")]
                if separator and key.strip() in ("flags", "Features")]
        require(bool(sets), "missing CPU features")
        if architecture in ("x86_64", "amd64"):
            require(all("avx2" in flags for flags in sets), "AVX2 unavailable")
            return "+avx2"
        if architecture in ("aarch64", "arm64"):
            require(all("asimd" in flags for flags in sets), "NEON unavailable")
            return "+neon"
    if system == "Darwin" and architecture == "arm64":
        result = subprocess.run(["sysctl", "-n", "hw.optional.neon"], text=True, capture_output=True, timeout=15, check=False)
        require(result.returncode == 0 and result.stdout.strip() == "1", "Apple NEON unavailable")
        return "+neon"
    raise ValueError("unsupported native MD5 HMAC host; cross/emulated is not native evidence")


def validate_output(output):
    require("test result: ok. 4 passed; 0 failed; 0 ignored;" in output, "MD5 native population")
    for marker in MARKERS:
        require(output.splitlines().count(marker) == 1, "MD5 native marker missing/duplicated")
    byte_expected = {f"{key}:{length}": hmac.new(bytes(((i * 0x9d) ^ 0x5a) & 255 for i in range(key)), bytes(((i * 0x3b) ^ 0xc1) & 255 for i in range(length)), hashlib.md5).hexdigest()
                     for key in (0, 1, 63, 64, 65, 80, 1024)
                     for length in (0, 1, 55, 56, 63, 64, 65, 127, 128, 4096)}
    bit_expected = {key.removeprefix("md5:"): value for key, value in legacy_hmac_bits.expected().items() if key.startswith("md5:")}
    for prefix, expected in (("LEGACY_MD5_BATCH_BYTE:", byte_expected), ("LEGACY_MD5_BATCH_BITS:", bit_expected),
                             ("LEGACY_MD5_BATCH_LANE:", legacy_hmac_md5_lanes.expected())):
        actual = {}
        for line in output.splitlines():
            if line.startswith(prefix):
                key, digest = line.removeprefix(prefix).rsplit(":", 1)
                require(key not in actual, "duplicate MD5 native identity")
                actual[key] = digest
        require(actual == expected, "MD5 native differential mismatch/population")


def main():
    selected = features()
    environment = {k: v for k, v in os.environ.items() if not k.startswith(("CARGO_", "RUST", "BRYNJA_"))}
    environment["RUSTFLAGS"] = "-C target-feature=" + selected
    environment["CARGO_TARGET_DIR"] = str(ROOT / "target/legacy-hmac-md5-native")
    for profile in ([], ["--release"]):
        command = ["cargo", "test", "--locked", "--offline", "-p", "brynja-legacy-hmac", "--features", "md5-batch",
                   *profile, "--test", "md5_batch", "--", "--ignored", "--nocapture", "--test-threads=1"]
        result = subprocess.run(command, cwd=ROOT, env=environment, text=True, capture_output=True, timeout=300, check=False)
        require(result.returncode == 0, "MD5 native run failed\n" + result.stdout[-4000:] + result.stderr[-4000:])
        validate_output(result.stdout)
        print("Legacy HMAC-MD5 native PASS:", "release" if profile else "debug", selected)


if __name__ == "__main__":
    main()
