#!/usr/bin/env python3
"""Validate live or captured GitHub protected-release controls."""

from __future__ import annotations

import argparse
import json
import subprocess
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "github-release-controls.toml"


def load_policy() -> dict:
    with POLICY_PATH.open("rb") as handle:
        return tomllib.load(handle)


def fetch_rulesets(repository: str) -> list[dict]:
    summary = json.loads(
        subprocess.check_output(
            ["gh", "api", f"repos/{repository}/rulesets"],
            cwd=ROOT,
            text=True,
        )
    )
    return [
        json.loads(
            subprocess.check_output(
                ["gh", "api", f"repos/{repository}/rulesets/{item['id']}"],
                cwd=ROOT,
                text=True,
            )
        )
        for item in summary
    ]


def require_equal(actual, expected, message: str) -> None:
    if actual != expected:
        raise RuntimeError(f"{message}: expected {expected!r}, got {actual!r}")


def validate_pull_request(rule: dict, policy: dict) -> None:
    parameters = rule.get("parameters", {})
    expected = policy["pull_request"]
    for name in (
        "required_approving_review_count",
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_last_push_approval",
    ):
        require_equal(
            parameters.get(name),
            expected[name],
            f"pull-request protection {name} drifted",
        )


def validate_code_scanning(rule: dict, policy: dict) -> None:
    tools = rule.get("parameters", {}).get("code_scanning_tools", [])
    expected = policy["code_scanning"]
    match = next((item for item in tools if item.get("tool") == expected["tool"]), None)
    if match is None:
        raise RuntimeError("required CodeQL protection is absent")
    for name in ("security_alerts_threshold", "alerts_threshold"):
        require_equal(
            match.get(name),
            expected[name],
            f"CodeQL {name} drifted",
        )


def bypass_identity(entry: dict) -> tuple[int | None, str, str]:
    return (
        entry.get("actor_id"),
        entry.get("actor_type", ""),
        entry.get("bypass_mode", ""),
    )


def expected_bypass(entry: dict) -> tuple[int | None, str, str]:
    return (
        entry.get("actor_id"),
        entry["actor_type"],
        entry["bypass_mode"],
    )


def validate_ruleset(
    ruleset: dict,
    policy: dict,
    *,
    require_bypass: bool = True,
) -> None:
    repository = policy["repository"]
    expected = policy["ruleset"]
    require_equal(
        ruleset.get("name"),
        repository["ruleset_name"],
        "ruleset name drifted",
    )
    require_equal(ruleset.get("target"), expected["target"], "ruleset target drifted")
    require_equal(
        ruleset.get("enforcement"),
        expected["enforcement"],
        "ruleset enforcement drifted",
    )
    ref_name = ruleset.get("conditions", {}).get("ref_name", {})
    require_equal(ref_name.get("include"), expected["include"], "ruleset refs drifted")
    require_equal(ref_name.get("exclude"), expected["exclude"], "ruleset excludes drifted")

    rules = ruleset.get("rules", [])
    by_type = {rule.get("type"): rule for rule in rules}
    if len(by_type) != len(rules):
        raise RuntimeError("ruleset repeats a rule type")
    required = set(expected["required_rules"])
    actual = set(by_type)
    if actual != required:
        raise RuntimeError(
            "protected rule inventory drifted: "
            f"missing={sorted(required - actual)}, extra={sorted(actual - required)}"
        )
    validate_pull_request(by_type["pull_request"], policy)
    validate_code_scanning(by_type["code_scanning"], policy)

    if require_bypass:
        actual_bypass = {
            bypass_identity(entry) for entry in ruleset.get("bypass_actors", [])
        }
        expected_bypass_actors = {
            expected_bypass(entry) for entry in policy.get("bypass", [])
        }
        if actual_bypass != expected_bypass_actors:
            raise RuntimeError("ruleset bypass identities or modes drifted")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--snapshot",
        type=Path,
        help="Validate a captured ruleset list instead of querying GitHub.",
    )
    parser.add_argument(
        "--public",
        action="store_true",
        help=(
            "Validate controls visible to a read-only token; the release gate "
            "must still validate protected bypass identities."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy()
    if args.snapshot is None:
        rulesets = fetch_rulesets(policy["repository"]["name"])
    else:
        rulesets = json.loads(args.snapshot.read_text(encoding="utf-8"))
    target = [
        ruleset
        for ruleset in rulesets
        if ruleset.get("name") == policy["repository"]["ruleset_name"]
    ]
    if len(target) != 1:
        raise RuntimeError("expected exactly one protected main-branch ruleset")
    validate_ruleset(target[0], policy, require_bypass=not args.public)
    print("GitHub main protection matches the committed release-control policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
