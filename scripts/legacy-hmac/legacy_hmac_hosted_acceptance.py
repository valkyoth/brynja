"""Exact protected legacy consumer graph and source-only package boundary."""
from pathlib import Path
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
    "src/lib.rs", "src/strict_execution/mod.rs", "src/strict_execution/types.rs",
    "src/strict_execution/worker.rs", "src/strict_execution/tests.rs",
    "src/strict_execution/tests/native.rs"})


def members(names):
    # Reuse path/duplicate checks, but pin this separate crate's exact population.
    from unittest.mock import patch
    import legacy_hmac_acceptance as leaf
    with patch.object(leaf, "REQUIRED", FILES):
        leaf_members(names)


def graph(document, roots, consumer):
    packages = document["packages"]
    require(len(packages) == len(FEATURES) and {p["name"] for p in packages} == set(FEATURES),
            "hosted packaged dependency closure")
    identities = {p["id"]: p["name"] for p in packages}
    require(len(identities) == len(packages), "duplicate hosted package identity")
    for package in packages:
        path = consumer if package["name"] == "legacy-hosted-external" else roots[package["name"]]
        require(package["source"] is None and Path(package["manifest_path"]).resolve() == path.resolve() / "Cargo.toml",
                "hosted dependency escaped archive")
    nodes = document["resolve"]["nodes"]
    require(len(nodes) == len(FEATURES) and {n["id"] for n in nodes} == set(identities), "hosted resolve population")
    actual = {identities[n["id"]]: set(n["features"]) for n in nodes}
    require(actual == FEATURES, "hosted feature closure: " + repr(actual))


def runtime(output, count):
    require(f"test result: ok. {count} passed; 0 failed; 0 ignored;" in output,
            "hosted runtime population")
