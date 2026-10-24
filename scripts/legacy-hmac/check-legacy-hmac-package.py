#!/usr/bin/env python3
"""Run real source-only legacy HMAC archives, graph isolation and independent vectors."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
from unittest.mock import patch

from legacy_hmac_acceptance import NAMES, isolation, members, packaged_graph, require
import legacy_hmac_bits
import legacy_hmac_native
import legacy_hmac_md5_native
import legacy_hmac_negatives

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "scripts/repository"))
sys.path.append(str(ROOT / "scripts/sha2"))
import facade_cargo_environment as cargo_environment
import sha2_public_api as packaging


def run(command, directory, environment):
    cargo_environment.check(directory, environment)
    result = subprocess.run(command, cwd=directory, env=environment, text=True,
                            capture_output=True, check=False, timeout=300)
    require(result.returncode == 0, f"command failed: {command}\n{result.stdout[-4000:]}\n{result.stderr[-4000:]}")
    return result.stdout


def oracle(output):
    expected = {}
    for name in ("md5", "sha1"):
        for key_length in (0, 1, 63, 64, 65, 80, 1024):
            for length in (0, 1, 55, 56, 63, 64, 65, 127, 128, 4096):
                expected[f"{name}:{key_length}:{length}"] = hmac.new(
                    bytes([0xa7]) * key_length, bytes([0x39]) * length,
                    getattr(hashlib, name)).hexdigest()
    actual = {}
    for line in output.splitlines():
        identity, digest = line.rsplit(":", 1)
        require(identity not in actual, "duplicate differential identity")
        actual[identity] = digest
    require(actual == expected, "independent hashlib/hmac differential mismatch or missing population")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha1-native", action="store_true", help="also require actual native SHA1 execution from extracted archives")
    parser.add_argument("--md5-native", action="store_true", help="also require actual native MD5 SIMD HMAC from extracted archives")
    args = parser.parse_args()
    selected = legacy_hmac_native.features() if args.sha1_native else None
    md5_selected = legacy_hmac_md5_native.features() if args.md5_native else None
    specifications = tuple((name, tomllib.loads(
        (ROOT / "crates" / name / "Cargo.toml").read_text())["package"]["version"],
        ("src/lib.rs",)) for name in NAMES)
    with cargo_environment.private_directory(ROOT) as temporary:
        directory = Path(temporary)
        environment = {k: v for k, v in os.environ.items() if not k.startswith(("CARGO_", "RUST", "BRYNJA_"))}
        environment["CARGO_HOME"] = str(directory / "cargo-home")
        environment["CARGO_TARGET_DIR"] = str(directory / "consumer-target")
        cargo_environment.check(ROOT, environment)
        # Keep the existing safe extraction and Cargo environment rules unchanged.
        with patch.object(packaging, "PACKAGING_PACKAGES", specifications), patch.dict(os.environ, environment, clear=True):
            roots = packaging.package_roots(directory)
        leaf = roots["brynja-legacy-hmac"]
        members(str(path.relative_to(leaf)) for path in leaf.rglob("*") if path.is_file())
        archive = directory / "target/package/brynja-legacy-hmac-0.1.0.crate"
        print(f"Legacy HMAC source-only archive: {archive.stat().st_size} bytes")
        consumer = directory / "consumer"
        (consumer / "src").mkdir(parents=True)
        manifest = ('[workspace]\n[package]\nname="legacy-hmac-external"\nversion="0.0.0"\n'
                    'edition="2024"\n[features]\ndefault=[]\nsha1-execution=["brynja-legacy-hmac/sha1-execution"]\n'
                    'md5-batch=["brynja-legacy-hmac/md5-batch"]\n'
                    '[dependencies]\nbrynja-legacy-hmac={version="=0.1.0",default-features=false}\n'
                    '[patch.crates-io]\n')
        manifest += "".join(f'{name}={{path={json.dumps(str(path))}}}\n' for name, path in roots.items())
        (consumer / "Cargo.toml").write_text(manifest)
        shutil.copyfile(leaf / "README.md", consumer / "README.md")
        (consumer / "src/lib.rs").write_text('#![no_std]\n#![doc=include_str!("../README.md")]\n')
        shutil.copytree(ROOT / "crates/brynja-legacy-hmac/tests", consumer / "tests")
        # Synthetic liveness/drop probes compile the exact private source from
        # the archive, without adding a public test hook to the production API.
        (consumer / "src/execution").mkdir()
        shutil.copyfile(leaf / "src/execution/retained.rs", consumer / "src/execution/retained.rs")
        shutil.copyfile(leaf / "src/execution/retained/tests.rs", consumer / "src/execution/tests.rs")
        (consumer / "tests/retained.rs").write_text('use brynja_legacy_hmac::Error;\n#[path="../src/execution/retained.rs"] mod retained;\n')
        run(["cargo", "generate-lockfile", "--offline"], consumer, environment)
        graph = json.loads(run(["cargo", "metadata", "--offline", "--locked", "--format-version", "1"], consumer, environment))
        packaged_graph(graph, roots, consumer)
        for profile in ([], ["--release"]):
            for test, count in (("contracts", 5), ("rfc2202", 2), ("retained", 3)):
                output = run(["cargo", "test", "--offline", "--locked", *profile, "--test", test], consumer, environment)
                require(f"test result: ok. {count} passed; 0 failed; 0 ignored;" in output,
                        "packaged runtime population: " + test)
            output = run(["cargo", "test", "--offline", "--locked", *profile, "--all-features", "--doc"], consumer, environment)
            require("test result: ok. 2 passed; 0 failed; 0 ignored;" in output, "README execution")
            output = run(["cargo", "test", "--offline", "--locked", *profile, "--test", "oracle", "--", "--nocapture"], consumer, environment)
            require("test result: ok. 1 passed; 0 failed; 0 ignored;" in output, "oracle execution")
            prefix = "LEGACY_HMAC_ORACLE:"
            oracle("\n".join(line.removeprefix(prefix) for line in output.splitlines() if line.startswith(prefix)))
            prefix = "LEGACY_HMAC_BITS:"
            legacy_hmac_bits.validate("\n".join(line.removeprefix(prefix) for line in output.splitlines() if line.startswith(prefix)))
            output = run(["cargo", "test", "--offline", "--locked", *profile, "--features", "sha1-execution", "--test", "sha1_execution"], consumer, environment)
            require("test result: ok. 1 passed; 0 failed; 2 ignored;" in output, "generic accelerated rejection population")
            output = run(["cargo", "test", "--offline", "--locked", *profile, "--features", "md5-batch", "--test", "md5_batch"], consumer, environment)
            require("test result: ok. 1 passed; 0 failed; 4 ignored;" in output, "generic MD5 rejection population")
            if md5_selected is not None:
                native_environment = dict(environment, RUSTFLAGS="-C target-feature=" + md5_selected)
                output = run(["cargo", "test", "--offline", "--locked", *profile, "--features", "md5-batch",
                              "--test", "md5_batch", "--", "--ignored", "--nocapture", "--test-threads=1"], consumer, native_environment)
                legacy_hmac_md5_native.validate_output(output)
                print("Extracted legacy HMAC-MD5 native PASS:", "release" if profile else "debug", md5_selected)
            if selected is not None:
                native_environment = dict(environment, RUSTFLAGS="-C target-feature=" + selected)
                output = run(["cargo", "test", "--offline", "--locked", *profile, "--features", "sha1-execution",
                              "--test", "sha1_execution", "--", "--ignored", "--nocapture", "--test-threads=1"], consumer, native_environment)
                legacy_hmac_native.validate_output(output)
                print("Extracted legacy HMAC-SHA1 native PASS:", "release" if profile else "debug", selected)
        legacy_hmac_negatives.check(consumer, environment, run, cargo_environment)
        # Workspace-only resolution needs its existing registry cache. The real
        # extracted consumer above deliberately has an empty Cargo home. Keep
        # config rejection on this read-only graph invocation as well.
        workspace_environment = dict(environment)
        workspace_environment["CARGO_HOME"] = os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))
        graph = json.loads(run(["cargo", "metadata", "--offline", "--locked", "--all-features", "--format-version", "1"], ROOT, workspace_environment))
        isolation(graph)
        print("Legacy HMAC: extracted debug/release RFC vectors, contracts, README, 140 byte / 176 bit differentials per profile and normal-edge isolation PASS")


if __name__ == "__main__":
    main()
