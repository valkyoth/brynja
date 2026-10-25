"""Exact protected legacy consumer graph and source-only package boundary."""
from pathlib import Path
import re
from legacy_hmac_acceptance import require, members as leaf_members

HOST = "brynja-legacy-hmac-std"
FEATURES = {
    "legacy-hosted-external": set(),
    HOST: {"strict-execution"},
    "brynja-legacy-hmac": set(),
    "brynja-legacy-sha1": set(),
    "brynja-legacy-md5": set(),
    "brynja-core": {"default"},
    "brynja-hash-core": {"default"},
    "brynja-crypto-cpu": {"default"},
    "brynja-hash-sha2": {"default", "cpu"},
    "brynja-crypto-cpu-std": {"protected-memory"},
}
FILES = frozenset({"Cargo.toml", "Cargo.toml.orig", "LICENSE-APACHE", "LICENSE-MIT", "README.md",
    "src/lib.rs", "src/common.rs", "src/verification.rs", "src/strict_execution/mod.rs", "src/strict_execution/types.rs",
    "src/strict_execution/worker.rs", "src/strict_execution/tests.rs",
    "src/strict_execution/tests/native.rs",
    "src/macos_resident/mod.rs", "src/macos_resident/types.rs", "src/macos_resident/worker.rs",
    "src/macos_resident/tests.rs", "src/macos_resident/tests/native.rs",
    *(f"src/{profile}/{name}" for profile in ("strict_execution", "macos_resident")
      for name in ("sha1_compiled.rs", "sha1_compiled/worker.rs",
                   "sha1_compiled/tests.rs", "sha1_compiled/tests/native.rs",
                   "md5_compiled.rs", "md5_compiled/types.rs", "md5_compiled/worker.rs",
                   "md5_compiled/tests.rs", "md5_compiled/tests/native.rs"))})


def features(resident=False, accelerated=False, md5=False):
    result = {name: set(values) for name, values in FEATURES.items()}
    if resident:
        result[HOST] = {"macos-resident"}
        result["brynja-crypto-cpu-std"] = {"macos-resident"}
        result["brynja-hash-sha2"].add("general-sha512-t")
        result["brynja-hash-sha3"] = {"default"}
    if accelerated:
        result[HOST].add("macos-resident-sha1-acceleration" if resident else "strict-sha1-acceleration")
        result["brynja-legacy-hmac"].add("sha1-execution")
        result["brynja-legacy-sha1"].update(("cpu", "hardened-execution"))
    if md5:
        result[HOST].add("macos-resident-md5-batch" if resident else "strict-md5-batch")
        result["brynja-legacy-hmac"].add("md5-batch")
        result["brynja-legacy-md5"].update(("batch", "cpu", "hardened-execution"))
    return result


def members(names):
    # Reuse path/duplicate checks, but pin this separate crate's exact population.
    from unittest.mock import patch
    import legacy_hmac_acceptance as leaf
    with patch.object(leaf, "REQUIRED", FILES):
        leaf_members(names)


def graph(document, roots, consumer, resident=False, accelerated=False, md5=False):
    expected = features(resident, accelerated, md5)
    packages = document["packages"]
    require(len(packages) == len(expected) and {p["name"] for p in packages} == set(expected),
            "hosted packaged dependency closure")
    identities = {p["id"]: p["name"] for p in packages}
    require(len(identities) == len(packages), "duplicate hosted package identity")
    for package in packages:
        path = consumer if package["name"] == "legacy-hosted-external" else roots[package["name"]]
        require(package["source"] is None and Path(package["manifest_path"]).resolve() == path.resolve() / "Cargo.toml",
                "hosted dependency escaped archive")
    nodes = document["resolve"]["nodes"]
    require(len(nodes) == len(expected) and {n["id"] for n in nodes} == set(identities), "hosted resolve population")
    actual = {identities[n["id"]]: set(n["features"]) for n in nodes}
    require(actual == expected, "hosted feature closure: " + repr(actual))


def runtime(output, count):
    require(f"test result: ok. {count} passed; 0 failed; 0 ignored;" in output,
            "hosted runtime population")


PARITY_FILES = ('mod.rs', 'types.rs', 'worker.rs', 'sha1_compiled.rs',
                'sha1_compiled/worker.rs', 'md5_compiled.rs',
                'md5_compiled/types.rs', 'md5_compiled/worker.rs')


def normalized_wrapper(text):
    # A drift tripwire, not a Rust parser or proof of cleanup. Resource types
    # deliberately remain distinct; compiler/native qualification checks each.
    text = re.sub(r'(?m)^\s*//.*\n', '', text)
    # Linux-only resource-residency observation hooks have no production effect.
    text = re.sub(r'#\[cfg\(test\)\]\s*super::(?:super::)?tests::observe\(&state, staging, (?:destination|output)\);', '', text)
    for before, after in (('strict_execution', 'PROFILE'), ('macos_resident', 'PROFILE'),
                          ('Protected', 'Resource'), ('Resident', 'Resource'),
                          ('protected_memory', 'PROFILE'), ('strict-execution', 'PROFILE'),
                          ('macos-resident', 'PROFILE'),
                          ('strict-sha1-acceleration', 'PROFILE-sha1-acceleration'),
                          ('strict-md5-batch', 'PROFILE-md5-batch'), ('protected', 'resident')):
        text = text.replace(before, after)
    text = text.replace('::PROFILE::memory::', '::PROFILE::')
    text = re.sub(r'\s+', '', text)
    text = text.replace('::PROFILE::{self,memory::{ResourceBytes,ResourceStack},}',
                        '::PROFILE::{self,ResourceBytes,ResourceStack}')
    text = text.replace('Bits,Error,PublicDeclassification,ResourceBytes',
                        'Bits,Error,ResourceBytes,PublicDeclassification')
    return text


def wrapper_parity(source):
    for name in PARITY_FILES:
        left = normalized_wrapper((source / 'strict_execution' / name).read_text())
        right = normalized_wrapper((source / 'macos_resident' / name).read_text())
        require(left == right, 'legacy protected/resident wrapper drift: ' + name)
