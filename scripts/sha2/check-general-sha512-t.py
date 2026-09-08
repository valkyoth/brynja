#!/usr/bin/env python3
"""Validate and execute the public general SHA-512/t parameter/IV contract."""
import argparse
import subprocess

import general_sha512_t_policy as policy
import sha512_t_iv_oracle as oracle
import sha512_t_digest_oracle as digest_oracle
import general_sha512_t_cleanup as cleanup
import general_sha512_t_lifecycle as lifecycle
import general_sha512_t_acceptance as acceptance
import general_sha512_t_final as final


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        policy.write_review()
    policy.validate()
    if policy.contract.read(policy.ROOT, str(oracle.VECTORS.relative_to(policy.ROOT))) != oracle.render():
        raise ValueError("general IV oracle mismatch")
    if policy.contract.read(policy.ROOT, str(digest_oracle.CORPUS.relative_to(policy.ROOT))) != digest_oracle.render():
        raise ValueError("general digest oracle mismatch")
    commands = (
        ["cargo", "test", "--locked", "--offline", "-p", "brynja-hash-sha2", "--features", "general-sha512-t", "--test", "general", "--test", "general_hash"],
        ["cargo", "test", "--locked", "--offline", "-p", "brynja-hash-sha2", "--features", "general-sha512-t", "--lib", "general::"],
        ["cargo", "test", "--locked", "--offline", "--manifest-path", "assurance/general-sha512-t/Cargo.toml"],
    )
    for command in commands:
        subprocess.run(command, cwd=policy.ROOT, check=True, timeout=180)
    cleanup.main()
    lifecycle.run()
    acceptance.run()
    final.run()
    print("General SHA-512/t public descriptors and all-510 IV oracle: PASS")
    print("Ordinary/hardened byte/bit hashing: PASS; no CPU admission or FIPS validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
