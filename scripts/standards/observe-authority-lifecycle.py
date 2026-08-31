#!/usr/bin/env python3
"""Run a bounded network lifecycle observation without changing policy."""

from __future__ import annotations

import argparse
from pathlib import Path

import lifecycle_model as model
import lifecycle_network as network
import standards_lib as standards


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--observed-at", default=network.current_date())
    parser.add_argument("--write-freshness", action="store_true")
    args = parser.parse_args()
    register = model.load_json(model.REGISTER)
    model.validate_register(register)
    policy = model.read_policy()
    observations = network.observe(register, policy)
    result = network.artifact(register, observations, args.observed_at)
    network.write_json(args.artifact, result)
    if args.write_freshness:
        if result["result"] != "PASS":
            raise model.LifecycleError("cannot write freshness from unresolved drift")
        receipt = {
            "observed_at": args.observed_at,
            "register_sha256": standards.sha256(model.REGISTER.read_bytes()),
            "result": "PASS",
            "schema": 1,
        }
        network.write_json(model.FRESHNESS, receipt)
    print(f"authority lifecycle observation: {result['result']} ({len(observations)} new observations)")
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
