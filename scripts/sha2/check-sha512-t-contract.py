#!/usr/bin/env python3
"""Check the frozen general SHA-512/t authority and public API admission."""
import argparse
import sha512_t_contract as contract


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        contract.write_review()
    contract.validate()
    valid = [t for t in range(1, 512) if t != 384]
    if len({contract.descriptor(t)[0] for t in valid}) != 510:
        raise ValueError("incomplete parameter descriptors")
    print("General SHA-512/t contract: PASS; 510 parameter descriptors, 14 operation groups")
    print("Contract model gate; hashing/lifecycle/package execution is separate; final closure pending v0.24.29; no FIPS/CPU admission")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
