#!/usr/bin/env python3
"""Emit and check only HKDF operation-local scratch, on installed host compilers."""
import argparse
from pathlib import Path
import tomllib

import hkdf_operation_codegen as codegen
import hmac_verifiers as verifier

ROOT = verifier.ROOT
FIXTURE = ROOT / "assurance/hkdf-operation-cleanup"


def policy():
    manifest = tomllib.loads((FIXTURE / "Cargo.toml").read_text())
    codegen.require(manifest == {
        "package": {"name": "brynja-hkdf-operation-cleanup", "version": "0.0.0",
                    "edition": "2024", "rust-version": "1.90", "publish": False},
        "workspace": {},
        "dependencies": {"brynja-crypto": {"path": "../../crates/brynja-crypto", "default-features": False}},
        "profile": {"release": {"opt-level": 3, "lto": "fat", "codegen-units": 1, "overflow-checks": True}},
    }, "fixture build policy changed")


def collect(directory, compiler, family, panic):
    env = verifier.environment(directory)
    env["CARGO_PROFILE_RELEASE_PANIC"] = panic
    env["RUSTUP_AUTO_INSTALL"] = "0"
    env["CARGO_NET_OFFLINE"] = "true"
    command = ["cargo", "+" + compiler, "rustc", "--locked", "--offline", "--release", "--lib",
               "--target", "x86_64-unknown-linux-gnu"]
    if family == "modern":
        command += ["--manifest-path", str(FIXTURE / "Cargo.toml")]
        stem = "brynja_hkdf_operation_cleanup"
    else:
        command += ["-p", "brynja-legacy-hkdf", "--no-default-features"]
        stem = "brynja_legacy_hkdf"
    verifier.run([*command, "--", "--emit=mir,llvm-ir,asm"], env)
    artifacts = {}
    for extension in ("mir", "ll", "s"):
        paths = list((directory / "target/x86_64-unknown-linux-gnu/release/deps").glob(stem + "-*." + extension))
        codegen.require(len(paths) == 1, "ambiguous compiler artifacts")
        artifacts[extension] = paths[0].read_text()
    bodies = codegen.check(artifacts["ll"], family, panic)
    count = codegen.negative_controls(bodies, family)
    codegen.require("clear_owned_region" in artifacts["s"], "assembly clearing symbol absent")
    for identity, op in bodies:
        # MIR and assembly presence are identity checks only; flow obligations
        # are checked in the LLVM body, not by searching these text markers.
        method = op if family == "legacy" else identity + "::" + op
        codegen.require(method in artifacts["mir"], "MIR operation identity absent")
    print(f"HKDF {family} operation scratch: PASS; Rust {compiler}; x86_64; panic={panic}; "
          f"{len(bodies)} consumers; {count} rejected mutations", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("family", choices=("modern", "legacy"))
    args = parser.parse_args()
    policy()
    for compiler in ("1.90.0", "1.99.1"):
        for panic in ("abort", "unwind"):
            with verifier.cargo_environment.private_directory(ROOT) as directory:
                collect(Path(directory), compiler, args.family, panic)
    print(f"HKDF {args.family} operation scratch complete: 4 configurations; "
          "delegated core clearing; not whole-frame erasure or timing qualification")


if __name__ == "__main__":
    main()
