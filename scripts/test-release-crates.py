#!/usr/bin/env python3
"""Negative and positive tests for Brynja's per-crate release policy."""

from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_policy as policy  # noqa: E402
import release_crates as publisher  # noqa: E402
import release_train_tests as train_tests  # noqa: E402


def entry(
    previous: str,
    version: str,
    change: str,
    publish: bool,
) -> dict:
    return {
        "previous_version": previous,
        "version": version,
        "change": change,
        "publish": publish,
        "reason": "test fixture",
    }


def public_plan() -> dict:
    crates = {
        name: entry("0.3.0", "0.3.0", "unchanged", False)
        for name in policy.PUBLISH_ORDER
    }
    for name in policy.REPOSITORY_ONLY:
        crates[name] = entry("unpublished", "0.3.0", "repository", False)
    crates[policy.FACADE] = entry("0.3.0", "0.4.0", "code", True)
    return {
        "version": "0.4.0",
        "milestone": "0.4.0",
        "baseline": "0.3.5",
        "cumulative_milestones": ["0.4.0"],
        "stage": "public",
        "exceptional": False,
        "exception_reason": "",
        "crates": crates,
    }


def package(name: str, version: str, dependencies: tuple[str, ...] = ()) -> dict:
    return {
        "name": name,
        "version": version,
        "publish": [] if name in policy.REPOSITORY_ONLY else None,
        "dependencies": [
            {"name": dependency, "req": "=0.3.0"} for dependency in dependencies
        ],
    }


def packages() -> dict[str, dict]:
    result = {
        name: package(name, "0.3.0") for name in policy.PUBLISH_ORDER
    }
    result["brynja-pki"] = package("brynja-pki", "0.3.0", ("brynja-core",))
    result["brynja-tls13"] = package(
        "brynja-tls13",
        "0.3.0",
        ("brynja-core", "brynja-tls13-handshake"),
    )
    result[policy.FACADE] = package(
        policy.FACADE,
        "0.4.0",
        ("brynja-core", "brynja-tls"),
    )
    return result


def assert_fails(expected: str, function, *args) -> None:
    try:
        function(*args)
    except RuntimeError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r} in {error!r}") from error
        return
    raise AssertionError("expected validation failure")


def test_current_repository_plan() -> None:
    policy.validate_repository()


def test_facade_always_publishes_at_release_version() -> None:
    plan = public_plan()
    policy.validate_facade_entry(plan["crates"][policy.FACADE], "0.4.0")
    unchanged = entry("0.3.0", "0.4.0", "unchanged", False)
    assert_fails(
        "must publish on every public release tag",
        policy.validate_facade_entry,
        unchanged,
        "0.4.0",
    )


def test_unknown_stage_is_rejected() -> None:
    plan = public_plan()
    plan["stage"] = "foundation"
    original_load = policy.load_toml
    policy.load_toml = lambda _path: {
        "release": {
            "version": plan["version"],
            "milestone": plan["milestone"],
            "baseline": plan["baseline"],
            "cumulative_milestones": plan["cumulative_milestones"],
            "policy": "independent",
            "stage": plan["stage"],
            "exceptional": plan["exceptional"],
            "exception_reason": plan["exception_reason"],
        },
        "crates": plan["crates"],
    }
    try:
        assert_fails(
            "release stage must be public or internal",
            policy.release_plan,
            Path("ignored.toml"),
        )
    finally:
        policy.load_toml = original_load


def test_facade_cannot_be_publish_false() -> None:
    facade = entry("0.3.0", "0.4.0", "code", False)
    assert_fails(
        "must publish on every public release tag",
        policy.validate_facade_entry,
        facade,
        "0.4.0",
    )


def test_facade_version_must_advance() -> None:
    assert_fails(
        "release version must advance",
        policy.validate_facade_entry,
        entry("0.5.0", "0.4.0", "code", True),
        "0.4.0",
    )


def test_initial_publication_is_explicit() -> None:
    initial = entry("unpublished", "0.2.0", "initial", True)
    policy.validate_support_entry("brynja-core", initial)
    wrong = entry("unpublished", "0.2.0", "code", True)
    assert_fails(
        "first publication must use change=initial",
        policy.validate_support_entry,
        "brynja-core",
        wrong,
    )


def test_support_code_uses_independent_minor() -> None:
    changed = entry("0.7.2", "0.8.0", "code", True)
    policy.validate_support_entry("brynja-core", changed)
    assert_fails(
        "code version must be 0.8.0",
        policy.validate_support_entry,
        "brynja-core",
        entry("0.7.2", "0.9.0", "code", True),
    )


def test_patch_classes_use_next_patch() -> None:
    for change in ("bugfix", "dependency", "metadata"):
        policy.validate_support_entry(
            "brynja-core",
            entry("0.7.2", "0.7.3", change, True),
        )
        assert_fails(
            f"{change} version must be 0.7.3",
            policy.validate_support_entry,
            "brynja-core",
            entry("0.7.2", "0.8.0", change, True),
        )


def test_unchanged_support_is_not_republished() -> None:
    policy.validate_support_entry(
        "brynja-core",
        entry("0.7.2", "0.7.2", "unchanged", False),
    )
    assert_fails(
        "unchanged entry requires publish=false",
        policy.validate_support_entry,
        "brynja-core",
        entry("0.7.2", "0.7.2", "unchanged", True),
    )


def test_repository_crates_can_never_publish() -> None:
    for name in policy.REPOSITORY_ONLY:
        policy.validate_repository_entry(
            name,
            entry("unpublished", "0.3.0", "repository", False),
        )
    assert_fails(
        "must use change=repository and publish=false",
        policy.validate_repository_entry,
        "brynja-research-ssl1",
        entry("unpublished", "0.3.0", "initial", True),
    )


def test_product_crate_cannot_claim_repository_only() -> None:
    assert_fails(
        "is not classified as repository-only",
        policy.validate_support_entry,
        "brynja-core",
        entry("0.3.0", "0.3.0", "repository", False),
    )


def test_publish_plan_skips_unchanged_and_repository_crates() -> None:
    plan = public_plan()
    plan["crates"]["brynja-core"] = entry("0.3.0", "0.4.0", "code", True)
    assert policy.publish_plan(plan) == ("brynja-core", policy.FACADE)


def test_manifest_version_must_match_plan() -> None:
    plan = public_plan()
    fixture = packages()
    fixture["brynja-core"]["version"] = "9.9.9"
    assert_fails(
        "does not match planned",
        policy.verify_repository,
        fixture,
        plan,
    )


def test_internal_dependency_pins_are_exact() -> None:
    plan = public_plan()
    fixture = packages()
    fixture["brynja-pki"]["dependencies"][0]["req"] = "^0.3.0"
    assert_fails(
        "must pin brynja-core to =0.3.0",
        policy.verify_repository,
        fixture,
        plan,
    )


def test_publish_cannot_depend_on_unpublished_crate() -> None:
    plan = public_plan()
    plan["crates"]["brynja-tls"] = entry(
        "unpublished",
        "0.3.0",
        "unpublished",
        False,
    )
    fixture = packages()
    fixture["brynja-tls"]["publish"] = []
    facade_dependency = fixture[policy.FACADE]["dependencies"][1]
    assert facade_dependency["name"] == "brynja-tls"
    assert_fails(
        "publishes with unavailable dependency brynja-tls",
        policy.verify_repository,
        fixture,
        plan,
    )


def test_repository_manifest_stays_unpublishable() -> None:
    plan = public_plan()
    fixture = packages()
    fixture["brynja-research-ssl1"]["publish"] = None
    assert_fails(
        "manifest must be publish=false",
        policy.verify_repository,
        fixture,
        plan,
    )


def test_product_manifest_must_allow_crates_io() -> None:
    plan = public_plan()
    fixture = packages()
    fixture["brynja-core"]["publish"] = ["internal"]
    assert_fails(
        "manifest must be publishable",
        policy.verify_repository,
        fixture,
        plan,
    )


def test_dependency_order_is_checked() -> None:
    plan = public_plan()
    fixture = packages()
    fixture["brynja-core"]["dependencies"] = [
        {"name": "brynja-pki", "req": "=0.3.0"}
    ]
    assert_fails(
        "appears later in PUBLISH_ORDER",
        policy.verify_repository,
        fixture,
        plan,
    )


def test_release_candidates_parse_structurally() -> None:
    assert str(policy.parse_version("1.0.0-rc.1")) == "1.0.0-rc.1"
    assert_fails(
        "version must be",
        policy.parse_version,
        "1.0.0-preview.1",
    )


def test_post_tag_preflight_supplies_guarded_context() -> None:
    calls = []
    original_run = publisher.run
    publisher.run = lambda command, **kwargs: calls.append((command, kwargs))
    try:
        publisher.run_preflight(
            "0.1.0",
            dry_run=False,
            release_tag_at_head=True,
        )
    finally:
        publisher.run = original_run
    assert calls[0] == (
        ["scripts/release_0_1_gate.sh"],
        {
            "dry_run": False,
            "extra_env": {"BRYNJA_RELEASE_PUBLISH_TAG": "v0.1.0"},
        },
    )


def test_resume_must_select_a_published_crate() -> None:
    selected = ("brynja-core", policy.FACADE)
    assert publisher.selected_steps(policy.FACADE, selected) == (policy.FACADE,)
    assert_fails(
        "is not selected for this release",
        publisher.selected_steps,
        "brynja-pki",
        selected,
    )


def test_package_check_builds_without_uploading() -> None:
    calls = []
    original_run = publisher.run
    publisher.run = lambda command, **kwargs: calls.append((command, kwargs))
    try:
        publisher.package_archive("brynja-core")
    finally:
        publisher.run = original_run
    assert calls == [
        (
            ["cargo", "package", "--no-verify", "-p", "brynja-core"],
            {"dry_run": False},
        )
    ]


def test_package_check_lists_files_without_uploading() -> None:
    calls = []
    original_run = publisher.run
    publisher.run = lambda command, **kwargs: calls.append((command, kwargs))
    try:
        publisher.package_file_list("brynja-pki")
    finally:
        publisher.run = original_run
    assert calls == [
        (
            ["cargo", "package", "--list", "-p", "brynja-pki"],
            {"dry_run": False},
        )
    ]


def test_package_roots_exclude_new_internal_dependencies() -> None:
    fixture = packages()
    selected = ("brynja-core", "brynja-crypto", "brynja-pki", policy.FACADE)
    assert publisher.package_roots(selected, fixture) == (
        "brynja-core",
        "brynja-crypto",
    )


def run_tests() -> None:
    tests = (
        test_current_repository_plan,
        test_facade_always_publishes_at_release_version,
        test_unknown_stage_is_rejected,
        train_tests.test_internal_stop_requires_empty_publication,
        train_tests.test_checkpoint_requires_exact_cumulative_range,
        train_tests.test_early_public_checkpoint_requires_exception_reason,
        test_facade_cannot_be_publish_false,
        test_facade_version_must_advance,
        test_initial_publication_is_explicit,
        test_support_code_uses_independent_minor,
        test_patch_classes_use_next_patch,
        test_unchanged_support_is_not_republished,
        test_repository_crates_can_never_publish,
        test_product_crate_cannot_claim_repository_only,
        test_publish_plan_skips_unchanged_and_repository_crates,
        test_manifest_version_must_match_plan,
        test_internal_dependency_pins_are_exact,
        test_publish_cannot_depend_on_unpublished_crate,
        test_repository_manifest_stays_unpublishable,
        test_product_manifest_must_allow_crates_io,
        test_dependency_order_is_checked,
        test_release_candidates_parse_structurally,
        test_post_tag_preflight_supplies_guarded_context,
        test_resume_must_select_a_published_crate,
        test_package_check_builds_without_uploading,
        test_package_check_lists_files_without_uploading,
        test_package_roots_exclude_new_internal_dependencies,
    )
    for test in tests:
        test()
    print(f"{len(tests)} release-policy tests passed")


if __name__ == "__main__":
    run_tests()
