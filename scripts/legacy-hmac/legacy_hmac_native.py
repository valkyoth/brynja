#!/usr/bin/env python3
"""Explicit real SHA-1 HMAC execution; not release or compiler qualification."""
import hashlib
import hmac
import os
from pathlib import Path
import platform
import subprocess

from legacy_hmac_acceptance import require
import legacy_hmac_bits

ROOT = Path(__file__).resolve().parents[2]


def features():
    architecture, system = platform.machine().lower(), platform.system()
    if system == "Linux":
        information = Path("/proc/cpuinfo").read_text()
        flag_sets = [set(value.split()) for line in information.splitlines()
                     for key, separator, value in [line.partition(":")]
                     if separator and key.strip() in ("flags", "Features")]
        require(bool(flag_sets), "missing CPU feature information")
        if architecture in ("x86_64", "amd64"):
            require(all({"sha_ni", "sse2"} <= flags for flags in flag_sets), "SHA-NI unavailable")
            return "+sha,+sse2"
        if architecture in ("aarch64", "arm64"):
            require(all({"asimd", "sha1", "sha2"} <= flags for flags in flag_sets), "Arm SHA1 unavailable")
            return "+neon,+sha2"
    if system == "Darwin" and architecture == "arm64":
        for key in ("hw.optional.neon", "hw.optional.arm.FEAT_SHA1", "hw.optional.arm.FEAT_SHA256"):
            result = subprocess.run(["sysctl", "-n", key], text=True, capture_output=True, timeout=15, check=False)
            require(result.returncode == 0 and result.stdout.strip() == "1", "Apple SHA1 feature unavailable: " + key)
        return "+neon,+sha2"
    raise ValueError("unsupported native SHA1 HMAC host; cross/emulated runs are not native evidence")


def validate_output(output):
    require("test result: ok. 2 passed; 0 failed; 0 ignored;" in output, "native test population")
    require("LEGACY_SHA1_EXECUTION: 70 byte cases, 88 bit cases; no fallback" in output.splitlines(), "native execution marker")
    require("LEGACY_SHA1_LIFECYCLE: malformed outputs preserve executor; revocation is terminal" in output.splitlines(), "native lifecycle marker")
    expected = {}
    for length in (0, 1, 63, 64, 65, 80, 1024):
        for size in (0, 1, 55, 56, 63, 64, 65, 127, 128, 4096):
            expected[f"{length}:{size}"] = hmac.new(bytes([0xa7]) * length, bytes([0x39]) * size, hashlib.sha1).hexdigest()
    bit_expected = {identity.removeprefix("sha1:"): digest for identity, digest in legacy_hmac_bits.expected().items()
                    if identity.startswith("sha1:")}
    for prefix, wanted in (("LEGACY_SHA1_BYTE:", expected), ("LEGACY_SHA1_BITS:", bit_expected)):
        actual = {}
        for line in output.splitlines():
            if line.startswith(prefix):
                identity, digest = line.removeprefix(prefix).rsplit(":", 1)
                require(identity not in actual, "duplicate native differential identity")
                actual[identity] = digest
        require(actual == wanted, "native independent differential mismatch")


def main():
    selected = features()
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("CARGO_", "RUST", "BRYNJA_"))}
    environment["RUSTFLAGS"] = "-C target-feature=" + selected
    environment["CARGO_TARGET_DIR"] = str(ROOT / "target/legacy-hmac-sha1-native")
    for profile in ([], ["--release"]):
        command = ["cargo", "test", "--locked", "--offline", "-p", "brynja-legacy-hmac",
                   "--features", "sha1-execution", *profile, "--test", "sha1_execution",
                   "--", "--ignored", "--nocapture", "--test-threads=1"]
        result = subprocess.run(command, cwd=ROOT, env=environment, text=True, capture_output=True, timeout=300, check=False)
        require(result.returncode == 0, "native command failed\n" + result.stdout[-4000:] + result.stderr[-4000:])
        validate_output(result.stdout)
        print("Legacy HMAC-SHA1 native PASS:", "release" if profile else "debug", selected)


if __name__ == "__main__":
    main()
