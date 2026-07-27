#!/usr/bin/env python3
"""Negative fixtures for GitHub protected-release controls."""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-github-release-controls.py")
SPEC = importlib.util.spec_from_file_location("github_controls", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load GitHub control validator")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
POLICY = MODULE.load_policy()


def valid_ruleset() -> dict:
    return {
        "name": "Valkyoth Protect Main Branch",
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []},
        },
        "rules": [
            {"type": "creation"},
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "update"},
            {"type": "required_linear_history"},
            {"type": "required_signatures"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": True,
                    "require_last_push_approval": True,
                },
            },
            {
                "type": "code_scanning",
                "parameters": {
                    "code_scanning_tools": [
                        {
                            "tool": "CodeQL",
                            "security_alerts_threshold": "all",
                            "alerts_threshold": "all",
                        }
                    ]
                },
            },
        ],
        "bypass_actors": [
            {
                "actor_id": 1921261,
                "actor_type": "User",
                "bypass_mode": "always",
            },
            {
                "actor_id": None,
                "actor_type": "OrganizationAdmin",
                "bypass_mode": "always",
            },
        ],
    }


def assert_rejected(expected: str, ruleset: dict) -> None:
    try:
        MODULE.validate_ruleset(ruleset, POLICY)
    except RuntimeError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r} in {error!r}") from error
        return
    raise AssertionError("expected GitHub release controls to be rejected")


def mutate_rule(ruleset: dict, rule_type: str) -> dict:
    return next(rule for rule in ruleset["rules"] if rule["type"] == rule_type)


def main() -> int:
    MODULE.validate_ruleset(valid_ruleset(), POLICY)
    public = valid_ruleset()
    del public["bypass_actors"]
    MODULE.validate_ruleset(public, POLICY, require_bypass=False)

    inactive = valid_ruleset()
    inactive["enforcement"] = "evaluate"
    assert_rejected("enforcement drifted", inactive)

    wrong_ref = valid_ruleset()
    wrong_ref["conditions"]["ref_name"]["include"] = ["refs/heads/release"]
    assert_rejected("refs drifted", wrong_ref)

    deletion = valid_ruleset()
    deletion["rules"] = [rule for rule in deletion["rules"] if rule["type"] != "deletion"]
    assert_rejected("rule inventory drifted", deletion)

    duplicate = valid_ruleset()
    duplicate["rules"].append({"type": "deletion"})
    assert_rejected("repeats a rule type", duplicate)

    unsigned = valid_ruleset()
    unsigned["rules"] = [
        rule for rule in unsigned["rules"] if rule["type"] != "required_signatures"
    ]
    assert_rejected("rule inventory drifted", unsigned)

    no_review = valid_ruleset()
    mutate_rule(no_review, "pull_request")["parameters"][
        "required_approving_review_count"
    ] = 0
    assert_rejected("required_approving_review_count drifted", no_review)

    stale_review = valid_ruleset()
    mutate_rule(stale_review, "pull_request")["parameters"][
        "dismiss_stale_reviews_on_push"
    ] = False
    assert_rejected("dismiss_stale_reviews_on_push drifted", stale_review)

    no_codeowners = valid_ruleset()
    mutate_rule(no_codeowners, "pull_request")["parameters"][
        "require_code_owner_review"
    ] = False
    assert_rejected("require_code_owner_review drifted", no_codeowners)

    weak_codeql = valid_ruleset()
    mutate_rule(weak_codeql, "code_scanning")["parameters"][
        "code_scanning_tools"
    ][0]["alerts_threshold"] = "errors"
    assert_rejected("CodeQL alerts_threshold drifted", weak_codeql)

    bypass = valid_ruleset()
    bypass["bypass_actors"][0]["bypass_mode"] = "pull_request"
    assert_rejected("bypass identities or modes drifted", bypass)

    print(
        "GitHub release-control validator accepts read-only visibility and "
        "rejects 10 protection regressions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
