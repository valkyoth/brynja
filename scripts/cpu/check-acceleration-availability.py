#!/usr/bin/env python3
"""Check the default-off acceleration availability contract, not CPU execution."""
import argparse
import acceleration_availability as contract


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-review", action="store_true")
    args = parser.parse_args()
    if args.write_review:
        contract.write_review()
    contract.validate()
    print("Acceleration availability contract: PASS; 11 kernels, 29 identities, zero activations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
