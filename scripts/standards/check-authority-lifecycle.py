#!/usr/bin/env python3
"""Validate and reproduce the offline authority lifecycle register."""

from __future__ import annotations

import argparse
import datetime as dt

import lifecycle_model as model
import lifecycle_reviews as reviews_policy
import standards_lib as standards


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    expected = model.build_register()
    model.validate_register(expected)
    if args.write:
        model.REGISTER.write_bytes(standards.json_bytes(expected))
    elif model.REGISTER.read_bytes() != standards.json_bytes(expected):
        raise model.LifecycleError("authority lifecycle register changed; run checker --write")
    reviews = model.load_json(model.REVIEWS)
    reviews_policy.validate_reviews(reviews)
    if reviews["unresolved_observations"]:
        raise model.LifecycleError("unresolved authority drift blocks release readiness")
    freshness = model.load_json(model.FRESHNESS)
    if freshness["register_sha256"] != standards.sha256(model.REGISTER.read_bytes()) or freshness["result"] != "PASS":
        raise model.LifecycleError("authority freshness receipt is stale or not PASS")
    if args.release:
        observed = dt.date.fromisoformat(freshness["observed_at"])
        age = (dt.datetime.now(dt.timezone.utc).date() - observed).days
        maximum = model.read_policy()["monitor"]["maximum_release_age_days"]
        if age < 0 or age > maximum:
            raise model.LifecycleError(f"authority freshness receipt is {age} days old")
    print(f"authority lifecycle register covers {len(expected['authorities'])} locked authorities with no unresolved drift")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
