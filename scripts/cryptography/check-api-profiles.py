#!/usr/bin/env python3
"""Check or regenerate the cryptographic API-profile register."""

from __future__ import annotations

import argparse

import api_profile_model as model


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    policy = model.read_policy()
    surfaces = model.read_surfaces()
    register = model.build_register(policy, surfaces)
    expected_register = model.json_bytes(register)
    expected_coverage = model.render_coverage(register)
    if args.write:
        model.REGISTER.write_bytes(expected_register)
        model.COVERAGE.write_bytes(expected_coverage)
    elif not model.REGISTER.is_file() or model.REGISTER.read_bytes() != expected_register:
        model.fail("cryptographic API-profile register is stale; run with --write")
    elif not model.COVERAGE.is_file() or model.COVERAGE.read_bytes() != expected_coverage:
        model.fail("cryptographic API-profile coverage is stale; run with --write")
    print(
        f"cryptographic API register covers {len(register['capabilities'])} capabilities, "
        f"{len(register['current_secret_owners'])} current and "
        f"{len(register['registered_secret_owners'])} registered capability owners, and "
        f"{len(register['planned_secret_owners'])} planned secret owners"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
