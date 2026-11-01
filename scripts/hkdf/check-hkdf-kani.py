#!/usr/bin/env python3
"""Run only the selected HKDF public-bounds proofs, never a repository campaign."""
import argparse
from pathlib import Path
import re
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hmac"))
import hmac_verifiers as verifier

HARNESSES = {
    "modern": (
        "modern_output_admission_and_minimal_block_count",
        "modern_invalid_width_never_admitted",
        "modern_tls_field_admission_and_encoded_size",
        "modern_short_tls_destination_is_unchanged",
    ),
    "legacy": ("legacy_output_admission_and_minimal_block_count",),
}


def policy():
    directory = verifier.ROOT / "assurance/hkdf-policy"
    manifest = tomllib.loads((directory / "Cargo.toml").read_text())
    expected = {"name": "brynja-hkdf-policy-fixture", "version": "0.0.0",
                "edition": "2024", "rust-version": "1.90", "publish": False}
    if (set(manifest) != {"package", "workspace", "lints"}
            or manifest["package"] != expected or manifest["workspace"] != {}):
        raise ValueError("HKDF bounds fixture must remain dependency-free")
    lock = tomllib.loads((directory / "Cargo.lock").read_text())
    if lock != {"version": 4, "package": [{"name": expected["name"], "version": "0.0.0"}]}:
        raise ValueError("HKDF proof lock identity changed")
    source = (directory / "src/lib.rs").read_text()
    names = re.findall(r'#\[kani::proof\]\s+(?:#\[kani::unwind\(\d+\)\]\s+)?fn ([a-z_]+)\(\)', source)
    if tuple(names) != (*HARNESSES["modern"], *HARNESSES["legacy"]) or source.count("#[kani::proof]") != 5:
        raise ValueError("HKDF bounds proof population drift")
    for path, module in (("brynja-crypto/src/hkdf/parameters.rs", "modern"),
                         ("brynja-legacy-hkdf/src/policy.rs", "legacy")):
        if f'#[path = "../../../crates/{path}"]\nmod {module};' not in source:
            raise ValueError("HKDF proofs must compile the actual production predicates")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=HARNESSES)
    parser.add_argument("--policy-only", action="store_true")
    args = parser.parse_args()
    policy()
    names = HARNESSES[args.suite]
    if args.policy_only:
        print(f"HKDF {args.suite} bounds inventory: {len(names)} proofs; NOT executed")
        return
    pin = verifier.tool("kani")
    with verifier.cargo_environment.private_directory(verifier.ROOT) as temporary:
        env = verifier.environment(Path(temporary))
        env["CARGO_NET_OFFLINE"] = "true"
        cargo = ["cargo", "+" + pin["execution_toolchain"], "kani"]
        banner = verifier.run([*cargo, "--version"], env).strip()
        if banner != f'Kani Rust Verifier {pin["version"]} (cargo plugin)\nCBMC 6.11.0':
            raise ValueError("HKDF Kani binary identity differs from repository pin")
        for name in names:
            output = verifier.run([*cargo, "--manifest-path", "assurance/hkdf-policy/Cargo.toml",
                                   "--harness", "proofs::" + name, "--exact"], env)
            print(output, flush=True)
            if "Complete - 1 successfully verified harnesses, 0 failures, 1 total." not in output:
                raise ValueError("Expected exactly one successful harness execution")
        print(f"HKDF {args.suite} public bounds: PASS; {len(names)} proofs; no cryptographic proof claim")


if __name__ == "__main__":
    main()
