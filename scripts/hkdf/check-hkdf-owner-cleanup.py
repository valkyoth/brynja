#!/usr/bin/env python3
"""Compile selected real HKDF owners and check bounded destructor dispatch."""
import argparse
from pathlib import Path
import re
import tomllib

import hkdf_owner_codegen as codegen
import hmac_verifiers as verifier

ROOT = verifier.ROOT
FIXTURE = ROOT / "assurance/hkdf-owner-cleanup"


def policy():
    manifest = tomllib.loads((FIXTURE / "Cargo.toml").read_text())
    codegen.require(manifest == {
        "package": {"name": "brynja-hkdf-owner-cleanup", "version": "0.0.0",
                    "edition": "2024", "rust-version": "1.90", "publish": False},
        "workspace": {},
        "features": {"default": [], "modern": ["dep:brynja-crypto"],
                     "legacy": ["dep:brynja-legacy-hkdf"]},
        "dependencies": {name: {"path": "../../crates/" + name, "default-features": False,
                                "optional": True}
                         for name in ("brynja-crypto", "brynja-legacy-hkdf")},
        "profile": {"release": {"opt-level": 3, "lto": "fat", "codegen-units": 1,
                                "overflow-checks": True}},
    }, "fixture build policy changed")


def negative_controls(llvm, family, panic):
    """Mutation checks use the very same emitted functions as positive evidence."""
    mutations = {
        "wrong destructor": llvm.replace("OwnedSecretRegion", "OtherSecretRegion"),
        "missing observer": llvm.replace("%observer(", "%missing("),
        "wrong pointer": re.sub(r"store ptr %0,", "store ptr null,", llvm),
        "shortened range": re.sub(r"store i64 %1,", "store i64 0,", llvm),
        "short descriptor copy": llvm.replace("i64 24, i1 false)", "i64 16, i1 false)"),
        "missing cleanup": re.sub(r'(?:tail )?call void @[^\n]*OwnedSecretRegion[^\n]*\n', "", llvm),
        "early return": llvm.replace("start:\n", "start:\n  ret void\n", 1),
        "post-cleanup write": llvm.replace("  ret void", "  store i64 0, ptr %_5, align 8\n  ret void"),
        "wrong target": llvm.replace('target triple = "x86_64-unknown-linux-gnu"',
                                     'target triple = "aarch64-unknown-linux-gnu"'),
        "missing probe": llvm.replace("prk_sha", "unknown_sha", 1),
        "unknown instruction": llvm.replace("start:\n", "start:\n  fence seq_cst\n", 1),
        "uninitialized cleanup": re.sub(r"  store i64 %1,[^\n]*\n", "", llvm),
    }
    # Replace an actual symbol, not just the demangled comment above it.
    mutations["missing probe"] = llvm.replace("prk_sha", "unknown_sha")
    for name, mutant in mutations.items():
        codegen.require(mutant != llvm, "vacuous negative control: " + name)
        try:
            codegen.check(mutant, family, panic)
        except ValueError:
            continue
        raise ValueError("HKDF owner dispatch accepted negative control: " + name)
    return len(mutations)


def collect(directory, compiler, family, panic):
    env = verifier.environment(directory)
    env["CARGO_PROFILE_RELEASE_PANIC"] = panic
    env["RUSTUP_AUTO_INSTALL"] = "0"
    env["CARGO_NET_OFFLINE"] = "true"
    verifier.run(["cargo", "+" + compiler, "rustc", "--manifest-path", str(FIXTURE / "Cargo.toml"),
                  "--locked", "--offline", "--release", "--no-default-features", "--features", family,
                  "--lib", "--target", "x86_64-unknown-linux-gnu", "--", "--emit=mir,llvm-ir,asm"], env)
    artifacts = {}
    for extension in ("mir", "ll", "s"):
        paths = list((directory / "target/x86_64-unknown-linux-gnu/release/deps").glob(
            "brynja_hkdf_owner_cleanup-*." + extension))
        codegen.require(len(paths) == 1, "ambiguous emitted artifact")
        artifacts[extension] = paths[0].read_text()
    for kind in ("prk", "key"):
        for identity in codegen.IDENTITIES[family]:
            name = kind + "_" + identity
            owner = "Prk" if kind == "prk" and family == "modern" else "Sha1Prk" if kind == "prk" else "DerivedKey"
            codegen.require(re.search(r"^fn (?:\w+::)?" + name + r"\(_1: " + owner + r"<'_", artifacts["mir"], re.M),
                            "actual public owner MIR identity absent: " + name)
            codegen.require(name in artifacts["s"], "assembly probe absent: " + name)
    codegen.require("OwnedSecretRegion" in artifacts["s"], "assembly delegated destructor absent")
    count = codegen.check(artifacts["ll"], family, panic)
    negative = negative_controls(artifacts["ll"], family, panic)
    print(f"HKDF {family} owner dispatch: PASS; Rust {compiler}; x86_64; panic={panic}; "
          f"{count} probes; {negative} rejected mutations", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("family", choices=codegen.IDENTITIES)
    args = parser.parse_args()
    policy()
    for compiler in ("1.90.0", "1.99.1"):
        for panic in ("abort", "unwind"):
            with verifier.cargo_environment.private_directory(ROOT) as path:
                collect(Path(path), compiler, args.family, panic)
    print(f"HKDF {args.family} owner dispatch complete: 4 configurations; "
          "delegated core cleanup; no whole-frame erasure or timing claim")


if __name__ == "__main__":
    main()
