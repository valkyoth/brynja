#!/usr/bin/env python3
"""Positive and broken-fixture tests for lifecycle monitoring."""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

import lifecycle_model as model
import lifecycle_network as network
import lifecycle_reviews as reviews_policy
import standards_lib as standards


def rejects(call, text: str) -> None:
    try:
        call()
    except Exception as error:
        assert text in str(error), (text, str(error))
    else:
        raise AssertionError(f"accepted broken lifecycle fixture: {text}")


def one_row(register: dict, prefix: str = "nist:") -> dict:
    return next(row for row in register["authorities"] if row["id"].startswith(prefix))


def fake_register(row: dict) -> dict:
    return {"authorities": [row], "schema": 1}


def test() -> None:
    policy = model.read_policy()
    register = model.build_register(policy)
    model.validate_register(register, policy)
    reviews_policy.validate_reviews(model.load_json(model.REVIEWS))
    assert len(register["authorities"]) == 130
    assert {row["id"].split(":", 1)[0] for row in register["authorities"]} == {
        "iana", "itu", "nist", "rfc", "riscv"
    }
    assert all(row["affected_milestones"] for row in register["authorities"])
    assert any(row["affected_requirements"] for row in register["authorities"])

    broken = copy.deepcopy(register)
    broken["authorities"].append(copy.deepcopy(broken["authorities"][0]))
    rejects(lambda: model.validate_register(broken, policy), "130 unique ordered")
    for field, value, message in (
        ("upstream_state", "invented", "invalid lifecycle state"),
        ("brynja_state", "automatic-modern", "invalid lifecycle state"),
        ("reviewed_disposition", "ignore", "invalid review disposition"),
        ("content_sha256", "0", "invalid content hash"),
    ):
        broken = copy.deepcopy(register)
        broken["authorities"][0][field] = value
        rejects(lambda broken=broken: model.validate_register(broken, policy), message)

    baseline = copy.deepcopy(register)
    changed = copy.deepcopy(register)
    row = one_row(changed)
    row["content_sha256"] = "a" * 64
    assert model.compare_register(baseline, changed)[0]["state"] == "changed"
    assert model.compare_register(baseline, baseline) == []

    for first, second in (
        ("draft", "final"),
        ("final", "update-planned"),
        ("final", "superseded"),
        ("final", "withdrawn"),
    ):
        left = copy.deepcopy(register)
        right = copy.deepcopy(register)
        one_row(left)["upstream_state"] = first
        one_row(right)["upstream_state"] = second
        result = model.compare_register(left, right)[0]
        assert result["requested_action"] == "human-review"
        assert result["effective_brynja_state"] == one_row(left)["brynja_state"]

    left = copy.deepcopy(register)
    right = copy.deepcopy(register)
    one_row(left)["edition"] = "revision 2"
    one_row(right)["edition"] = "revision 1"
    assert model.compare_register(left, right)[0]["state"] == "rollback"
    right = copy.deepcopy(left)
    one_row(right)["metadata"]["note"] = "editorial metadata"
    assert model.compare_register(left, right)[0]["state"] == "changed"

    sample = model.observation(one_row(register), "changed", "replacement relation")
    retained = model.retain_unresolved([], [sample])
    assert len(model.retain_unresolved(retained, [])) == 1
    assert model.retain_unresolved(retained, [sample]) == retained
    rejects(
        lambda: reviews_policy.review_observation(
            retained[0],
            "implementation-update",
            corrective_milestone=None,
            evidence=["standards/source-ledger.json"],
            pentest="none",
            pentest_report=None,
        ),
        "corrective milestone",
    )
    review = reviews_policy.review_observation(
        retained[0],
        "no-effect",
        corrective_milestone=None,
        evidence=["standards/source-ledger.json"],
        pentest="not-required",
        pentest_report=None,
    )
    assert review["observation_id"] == retained[0]["id"]
    reviewed = {
        "observations": retained,
        "reviews": [review],
        "schema": 2,
        "unresolved_observations": [],
    }
    reviews_policy.validate_reviews(reviewed, enforce_history=False)
    original_prior = reviews_policy.prior_committed_reviews
    reviews_policy.prior_committed_reviews = lambda: copy.deepcopy(reviewed)
    try:
        rejects(
            lambda: reviews_policy.validate_append_only(
                {
                    "observations": [],
                    "reviews": [],
                    "schema": 2,
                    "unresolved_observations": [],
                }
            ),
            "observations history is not append-only",
        )
        rewritten = copy.deepcopy(reviewed)
        rewritten["reviews"][0]["reviewed_impact"] = "rewritten"
        rejects(
            lambda: reviews_policy.validate_append_only(rewritten),
            "reviews history is not append-only",
        )
    finally:
        reviews_policy.prior_committed_reviews = original_prior
    rejects(
        lambda: reviews_policy.review_observation(
            retained[0],
            "automatic-modern",
            corrective_milestone=None,
            evidence=["standards/source-ledger.json"],
            pentest="none",
            pentest_report=None,
        ),
        "invalid authority drift disposition",
    )
    reviews_policy.validate_reviews(
        {"observations": [], "reviews": [], "schema": 2, "unresolved_observations": []},
        enforce_history=False,
    )
    rejects(
        lambda: reviews_policy.validate_reviews(
            {
                "observations": retained,
                "reviews": [],
                "schema": 2,
                "unresolved_observations": retained + retained,
            },
            enforce_history=False,
        ),
        "duplicate or not archived",
    )
    fabricated = copy.deepcopy(reviewed)
    fabricated["reviews"][0]["observation_id"] = "fabricated"
    rejects(
        lambda: reviews_policy.validate_reviews(fabricated, enforce_history=False),
        "unknown observation",
    )
    mismatched = copy.deepcopy(reviewed)
    mismatched["reviews"][0]["affected_requirements"] = ["fabricated"]
    rejects(
        lambda: reviews_policy.validate_reviews(mismatched, enforce_history=False),
        "does not cover observation affected_requirements",
    )
    corrective = reviews_policy.review_observation(
        retained[0],
        "implementation-update",
        corrective_milestone="not-a-real-milestone",
        evidence=["standards/source-ledger.json"],
        pentest="exceptional-required",
        pentest_report="security/pentest/vnot-a-real-milestone.md",
    )
    fabricated = {
        "observations": retained,
        "reviews": [corrective],
        "schema": 2,
        "unresolved_observations": [],
    }
    rejects(
        lambda: reviews_policy.validate_reviews(fabricated, enforce_history=False),
        "corrective milestone is not in the release plan",
    )
    bound = copy.deepcopy(corrective)
    bound["corrective_milestone"] = "0.24.6"
    bound["pentest_report"] = "security/pentest/v0.24.6.md"
    sections = {
        "0.24.6": f"correction for {retained[0]['authority']} {retained[0]['id']}"
    }
    reviews_policy.validate_review(
        bound,
        retained[0],
        sections,
        pentest_validator=lambda _path, _milestone, _root: None,
    )

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        report = root / "security/pentest/v0.24.6.md"
        report.parent.mkdir(parents=True)
        report.write_text(
            "Version: v0.24.6\nStatus: PASS\nRetest: PASS\nOpen-Findings: 0\n"
        )
        reviews_policy.validate_pentest_report(
            "security/pentest/v0.24.6.md", "0.24.6", root
        )
        report.write_text(
            "Version: v0.24.6\nStatus: PASS\nRetest: PENDING\nOpen-Findings: 0\n"
        )
        rejects(
            lambda: reviews_policy.validate_pentest_report(
                "security/pentest/v0.24.6.md", "0.24.6", root
            ),
            "Retest: PASS",
        )

    redirect = network.ExactRedirectHandler()
    rejects(
        lambda: redirect.redirect_request(
            type("Request", (), {"full_url": "https://www.rfc-editor.org/a"})(),
            None, 302, "", {}, "https://example.com/b"
        ),
        "redirect-rejected",
    )
    rejects(lambda: network.landing_projection(b"<html></html>"), "no bounded visible identity")

    row = one_row(register)
    for message, state in (
        ("oversized response", "oversized"),
        ("malformed response", "malformed"),
        ("timed out", "unavailable"),
    ):
        def failed(_url, _maximum, message=message):
            raise model.LifecycleError(message)

        result = network.landing_observations(fake_register(row), policy, failed)
        assert result[0]["state"] == state

    empty_errata_row = next(
        item
        for item in register["authorities"]
        if item["id"].startswith("rfc:") and item["metadata"]["errata"] == []
    )
    malformed_errata = network.errata_observations(
        fake_register(empty_errata_row),
        policy,
        lambda _url, _maximum: b"<html><body>maintenance</body></html>",
    )
    assert len(malformed_errata) == 1
    assert malformed_errata[0]["state"] == "malformed"
    assert network.errata_observations(
        fake_register(empty_errata_row),
        policy,
        lambda _url, _maximum: (
            b'<p class="alert alert-info">No matching errata found.</p>'
        ),
    ) == []

    pass_artifact = network.artifact(register, [], "2026-08-31")
    assert pass_artifact["result"] == "PASS"
    failed_artifact = network.artifact(register, [sample], "2026-08-31")
    assert failed_artifact["result"] == "REVIEW REQUIRED"
    assert failed_artifact["unresolved_observations"]

    workflow = (model.ROOT / ".github/workflows/standards-lifecycle.yml").read_text()
    assert "schedule:" in workflow and "workflow_dispatch:" in workflow
    assert "observe-authority-lifecycle.py" in workflow
    assert "--write-freshness" not in workflow
    assert "permissions:\n  contents: read" in workflow
    tag_gate = (model.ROOT / "scripts/tag_gate.sh").read_text()
    assert "check-authority-lifecycle.py --release" in tag_gate
    assert "observe-authority-lifecycle.py" in tag_gate
    assert 'mktemp -d "${TMPDIR:-/tmp}/brynja-authority.XXXXXX"' in tag_gate
    assert "brynja-authority-lifecycle-observation.json" not in tag_gate

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "artifact.json"
        network.write_new_json(path, pass_artifact)
        assert json.loads(path.read_text()) == pass_artifact
        rejects(
            lambda: network.write_new_json(path, pass_artifact),
            "refusing existing artifact path",
        )
        network.write_existing_json(path, failed_artifact)
        assert json.loads(path.read_text()) == failed_artifact
        victim = Path(directory) / "victim.txt"
        victim.write_text("unchanged")
        link = Path(directory) / "linked-artifact.json"
        try:
            link.symlink_to(victim)
        except OSError:
            pass
        else:
            rejects(
                lambda: network.write_new_json(link, pass_artifact),
                "refusing existing artifact path",
            )
            rejects(
                lambda: network.write_existing_json(link, pass_artifact),
                "not a regular file",
            )
            assert victim.read_text() == "unchanged"
    assert standards.sha256(model.REGISTER.read_bytes()) == model.load_json(model.FRESHNESS)["register_sha256"]
    print("authority lifecycle monitor rejects status, content, replay, redirect, bound, outage, and review regressions")


if __name__ == "__main__":
    test()
