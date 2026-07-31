#!/usr/bin/env python3
"""Check or regenerate deterministic v0.4.0 assurance evidence."""

from __future__ import annotations

import argparse

import assurance_policy as assurance


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--targets", action="store_true")
    args = parser.parse_args()

    policy = assurance.read_policy()
    if args.targets:
        for target in assurance.TARGETS:
            print(target)
        return 0
    if args.network:
        assurance.network_check(policy)
    expected = assurance.json_bytes(assurance.build_evidence(policy))
    if args.write:
        assurance.EVIDENCE.write_bytes(expected)
    elif not assurance.EVIDENCE.is_file():
        assurance.fail("missing generated assurance evidence")
    elif assurance.EVIDENCE.read_bytes() != expected:
        assurance.fail("generated assurance evidence is stale")
    print(
        f"assurance policy binds {len(assurance.TARGETS)} bare-metal targets "
        f"and {len(policy['tools'])} external tool pins"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
