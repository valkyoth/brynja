#!/usr/bin/env python3
"""Test real HMAC archives downstream; standalone fixtures/evidence stay in Git."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
from unittest.mock import patch

from hmac_package import validate_members
import hmac_faults
import hmac_acceptance
import hmac_execution_acceptance
import hmac_adapter_native

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "scripts/repository"))
sys.path.append(str(ROOT / "scripts/sha2"))
import facade_cargo_environment as cargo_environment
import sha2_public_api as packaging

NAMES = ("brynja-core", "brynja-hash-core", "brynja-crypto-cpu",
         "brynja-hash-sha2", "brynja-hash-sha3", "brynja-mac-hmac")


def run(command, directory, environment):
    cargo_environment.check(directory, environment)
    result = subprocess.run(command, cwd=directory, env=environment, check=False,
                            text=True, capture_output=True, timeout=300)
    if result.returncode:
        raise RuntimeError(f"HMAC package command failed ({result.returncode}): {command}\n"
                           + result.stdout[-6000:] + result.stderr[-6000:])
    return result.stdout


def consumer_manifest(roots):
    # The fractional-profile regression composes the public SHA-2 hash directly.
    # This is a test-only edge to the same extracted, already transitive archive.
    manifest = ('[workspace]\n[package]\nname="hmac-external"\nversion="0.0.0"\n'
                'edition="2024"\n[dependencies]\n'
                'brynja-mac-hmac={version="=0.1.0", default-features=false}\n'
                '[dev-dependencies]\n'
                'brynja-hash-sha2={version="=0.1.0", default-features=false}\n'
                '[patch.crates-io]\n')
    return manifest + "".join(f'{name}={{path={json.dumps(str(path))}}}\n' for name, path in roots.items())


def test_profiles(consumer, environment):
    for profile in ([], ["--release"]):
        for test, count in (("vectors", 7), ("lifecycle", 11), ("bounded", 13), ("bits", 12), ("general", 6), ("tag_policy", 3)):
            output = run(["cargo", "test", "--offline", "--locked", *profile, "--test", test], consumer, environment)
            if f"test result: ok. {count} passed; 0 failed; 0 ignored;" not in output:
                raise ValueError("HMAC packaged test population changed: " + test + "\n" + output[-6000:])
        output = run(["cargo", "test", "--offline", "--locked", *profile, "--doc"], consumer, environment)
        if "test result: ok. 3 passed; 0 failed; 0 ignored;" not in output:
            raise ValueError("HMAC README example population changed\n" + output[-6000:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-std-target", help="also build the extracted consumer for an installed bare-metal target")
    parser.add_argument("--adapter-kernel", choices=("sha256", "sha512", "keccak"), action="append",
                        help="explicit real native adapter handoffs; refuses unsupported host instructions")
    args = parser.parse_args()
    if args.adapter_kernel and len(args.adapter_kernel) != len(set(args.adapter_kernel)):
        parser.error("duplicate adapter kernel")
    specifications = tuple((name, tomllib.loads(
        (ROOT / "crates" / name / "Cargo.toml").read_text())["package"]["version"],
        ("src/lib.rs",)) for name in NAMES)
    with cargo_environment.private_directory(ROOT) as temporary:
        directory = Path(temporary)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("CARGO_", "RUST", "BRYNJA_"))}
        environment["CARGO_HOME"] = str(directory / "empty-cargo-home")
        environment["CARGO_TARGET_DIR"] = str(directory / "consumer-target")
        cargo_environment.check(ROOT, environment)
        # Reuse the existing real-archive builder and safe extractor. This
        # changes only its selected package population in this process.
        with patch.object(packaging, "PACKAGING_PACKAGES", specifications), \
                patch.dict(os.environ, environment, clear=True):
            roots = packaging.package_roots(directory)
        leaf = roots["brynja-mac-hmac"]
        members = [str(path.relative_to(leaf)) for path in leaf.rglob("*") if path.is_file()]
        validate_members(members)
        archive = directory / "target/package/brynja-mac-hmac-0.1.0.crate"
        print(f"HMAC source/metadata archive: {len(members)} files; {archive.stat().st_size} compressed bytes")
        consumer = directory / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "Cargo.toml").write_text(consumer_manifest(roots))
        shutil.copyfile(leaf / "README.md", consumer / "README.md")
        (consumer / "src/lib.rs").write_text('#![no_std]\n#![doc=include_str!("../README.md")]\n')
        # Acceptance tests deliberately live outside the runtime archive.
        shutil.copytree(ROOT / "crates/brynja-mac-hmac/tests", consumer / "tests")
        run(["cargo", "generate-lockfile", "--offline"], consumer, environment)
        graph = json.loads(run(["cargo", "metadata", "--offline", "--locked", "--format-version", "1"], consumer, environment))
        expected = (set(NAMES) - {"brynja-crypto-cpu"}) | {"hmac-external"}
        if {p["name"] for p in graph["packages"]} != expected:
            raise ValueError("unexpected active HMAC dependency closure")
        for package in graph["packages"]:
            location = consumer if package["name"] == "hmac-external" else roots[package["name"]]
            if package["source"] is not None or Path(package["manifest_path"]).resolve() != location / "Cargo.toml":
                raise ValueError("HMAC dependency escaped extracted archives")
        test_profiles(consumer, environment)
        print("HMAC extracted archive: debug/release vectors, lifecycle, bounded, bits, general, tag policy and README PASS")
        hmac_acceptance.negatives(consumer, environment, args.no_std_target)
        hmac_acceptance.mutants(roots, consumer, environment)
        hmac_faults.check(roots, directory, environment)
        hmac_execution_acceptance.check(consumer, environment, roots)
        hmac_execution_acceptance.check(consumer, environment, roots, runtime=True)
        hmac_execution_acceptance.lifecycle(roots, directory, environment)
        for kernel in args.adapter_kernel or []:
            hmac_adapter_native.check(roots, directory, environment, kernel)


if __name__ == "__main__":
    main()
