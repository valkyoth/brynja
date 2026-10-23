#!/usr/bin/env python3
"""Bounded legacy-HMAC timing screen; never a native qualification receipt."""
import argparse
from pathlib import Path
import legacy_hmac_timing as timing
import legacy_hmac_timing_runner as runner


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--route", choices=timing.ROUTES, required=True)
    parser.add_argument("--family", choices=timing.WIDTHS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = runner.observe(args.route, args.family, args.output)
    print(f"Legacy HMAC {args.route}/{args.family}: {len(result['campaigns'])} campaigns; "
          f"{result['signals']} signals; observation={args.output}")


if __name__ == "__main__":
    main()
