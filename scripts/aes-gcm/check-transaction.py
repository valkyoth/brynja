#!/usr/bin/env python3
"""Prove the two output layouts using the repository-pinned Kani and CBMC."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hmac"))
import hmac_verifiers as verifier


def main():
    pin = verifier.tool("kani")
    cargo = ["cargo", "+" + pin["execution_toolchain"], "kani"]
    with verifier.cargo_environment.private_directory(verifier.ROOT) as directory:
        env = verifier.environment(Path(directory))
        env["CARGO_NET_OFFLINE"] = "true"
        if verifier.run([*cargo, "--version"], env).strip() != (
            f'Kani Rust Verifier {pin["version"]} (cargo plugin)\nCBMC 6.11.0'
        ):
            raise ValueError("unexpected Kani/CBMC identity")
        for name in ("separate_commit", "in_place_commit"):
            output = verifier.run([*cargo, "--manifest-path", "assurance/aes-gcm-transaction/Cargo.toml",
                                   "--harness", "proofs::" + name, "--exact"], env)
            if "Complete - 1 successfully verified harnesses, 0 failures, 1 total." not in output:
                raise ValueError(f"missing successful proof for {name}")
            print(f"{name}: verified", flush=True)
    print("AES_GCM_TRANSACTION_PROOFS_COMPLETE")


if __name__ == "__main__":
    main()
