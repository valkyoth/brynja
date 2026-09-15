#!/usr/bin/env python3
"""Run a bounded network lifecycle observation without changing policy."""

from __future__ import annotations

import argparse
from pathlib import Path

import lifecycle_model as model
import lifecycle_network as network
import lifecycle_local as local
import standards_lib as standards


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--observed-at", default=network.current_date())
    parser.add_argument("--write-freshness", action="store_true")
    parser.add_argument("--allow-verified-local", action="store_true",
                        help="use hash-verified local document bytes during transport outages")
    args = parser.parse_args()
    register = model.load_json(model.REGISTER)
    model.validate_register(register)
    policy = model.read_policy()
    observer = local.LocalObserver(register, policy) if args.allow_verified_local else None
    observations = network.observe(register, policy, observer.fetch) if observer else network.observe(register, policy)
    result = network.artifact(register, observations, args.observed_at)
    if observer:
        result = observer.annotate(result)
    network.write_new_json(args.artifact, result)
    if args.write_freshness:
        if not local.permits_freshness(result):
            raise model.LifecycleError("cannot write freshness from unresolved drift or offline documents")
        receipt = {
            "observed_at": args.observed_at,
            "register_sha256": standards.sha256(model.REGISTER.read_bytes()),
            "result": "PASS",
            "schema": 1,
        }
        network.write_existing_json(model.FRESHNESS, receipt)
    print(f"authority lifecycle observation: {result['result']} ({len(observations)} new observations)")
    if result.get("offline_documents"):
        print(f"verified-local fallbacks: {len(result['offline_documents'])}; remote freshness unverified")
    return 0 if local.permits_release(result) else 1


if __name__ == "__main__":
    raise SystemExit(main())
