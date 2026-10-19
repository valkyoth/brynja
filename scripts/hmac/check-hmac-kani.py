#!/usr/bin/env python3
"""Prove the actual HMAC public-length predicates; not the hash construction."""
import argparse
import re
import tomllib

import hmac_verifiers as verifier

HARNESS_NAMES = ("tag_length_matches_exact_public_policy", "output_length_never_admits_prefix_or_extension")


def policy():
    directory = verifier.ROOT / "assurance/hmac-policy"
    manifest = tomllib.loads((directory / "Cargo.toml").read_text())
    expected = {"name": "brynja-hmac-policy-fixture", "version": "0.0.0", "edition": "2024",
                "rust-version": "1.90", "publish": False}
    if (set(manifest) != {"package", "workspace", "lints"} or manifest["package"] != expected
            or manifest["workspace"] != {}):
        raise ValueError("HMAC bounds proof must remain dependency-free")
    lock = tomllib.loads((directory / "Cargo.lock").read_text())
    if lock != {"version": 4, "package": [{"name": expected["name"], "version": "0.0.0"}]}:
        raise ValueError("HMAC proof lock identity changed")
    source = (verifier.ROOT / "assurance/hmac-policy/src/lib.rs").read_text()
    names = re.findall(r'#\[kani::proof\]\s+fn ([a-z_]+)\(\)', source)
    if tuple(names) != HARNESS_NAMES or source.count("#[kani::proof]") != 2:
        raise ValueError("HMAC policy proof population drift")
    if '#[path = "../../../crates/brynja-mac-hmac/src/policy.rs"]\nmod policy;' not in source:
        raise ValueError("HMAC proof must compile the runtime policy source")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy-only", action="store_true")
    args = parser.parse_args()
    policy()
    if args.policy_only:
        print("HMAC Kani inventory: 2 runtime-predicate proofs; NOT executed")
        return
    pin = verifier.tool("kani")
    with verifier.cargo_environment.private_directory(verifier.ROOT) as temporary:
        from pathlib import Path
        env = verifier.environment(Path(temporary))
        env["CARGO_NET_OFFLINE"] = "true"
        cargo = ["cargo", "+" + pin["execution_toolchain"], "kani"]
        banner = verifier.run([*cargo, "--version"], env).strip()
        if banner != f'Kani Rust Verifier {pin["version"]} (cargo plugin)\nCBMC 6.11.0':
            raise ValueError("HMAC Kani binary identity differs from the repository pin")
        output = verifier.run([*cargo, "--manifest-path", "assurance/hmac-policy/Cargo.toml"], env)
        print(output)
        if "Complete - 2 successfully verified harnesses, 0 failures, 2 total." not in output:
            raise ValueError("HMAC proof execution population missing")
        print("HMAC public-length Kani proofs: PASS; 2 proofs, no cryptographic proof claim")


if __name__ == "__main__":
    main()
