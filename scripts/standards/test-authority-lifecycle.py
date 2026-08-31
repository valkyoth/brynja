#!/usr/bin/env python3
"""Positive and broken-fixture tests for lifecycle monitoring."""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

import lifecycle_model as model
import lifecycle_network as network
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
        lambda: model.review_observation(
            retained[0], "implementation-update", corrective_milestone=None, pentest="none"
        ),
        "corrective milestone",
    )
    review = model.review_observation(
        retained[0],
        "implementation-update",
        corrective_milestone="0.24.5.1",
        pentest="exceptional-required",
    )
    assert review["observation_id"] == retained[0]["id"]
    assert model.review_observation(
        retained[0], "no-effect", corrective_milestone=None, pentest="not-required"
    )["disposition"] == "no-effect"
    rejects(
        lambda: model.review_observation(
            retained[0], "automatic-modern", corrective_milestone=None, pentest="none"
        ),
        "invalid authority drift disposition",
    )
    model.validate_reviews({"reviews": [], "schema": 1, "unresolved_observations": []})
    rejects(
        lambda: model.validate_reviews(
            {"reviews": [], "schema": 1, "unresolved_observations": retained + retained}
        ),
        "duplicate or authorizing",
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

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "artifact.json"
        network.write_json(path, pass_artifact)
        assert json.loads(path.read_text()) == pass_artifact
    assert standards.sha256(model.REGISTER.read_bytes()) == model.load_json(model.FRESHNESS)["register_sha256"]
    print("authority lifecycle monitor rejects status, content, replay, redirect, bound, outage, and review regressions")


if __name__ == "__main__":
    test()
