#!/usr/bin/env python3
"""Positive and broken fixtures for the v0.4.0 assurance boundary."""

from __future__ import annotations

import copy
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import assurance_differential as differential
import assurance_mutation as mutation
import assurance_policy as assurance
from assurance_process import run_bounded


ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "scripts" / "assurance-fixture-adapter.py"


@contextmanager
def fails_with(message: str):
    try:
        yield
    except RuntimeError as error:
        if message not in str(error):
            raise AssertionError(f"expected {message!r}, got {error!r}") from error
    else:
        raise AssertionError(f"expected failure containing {message!r}")


def command(mode: str) -> list[str]:
    return [sys.executable, str(ADAPTER), mode]


def test_policy_and_evidence_are_deterministic() -> None:
    policy = assurance.read_policy()
    first = assurance.json_bytes(assurance.build_evidence(policy))
    second = assurance.json_bytes(assurance.build_evidence(policy))
    assert first == second


def test_weakened_harness_fails() -> None:
    policy = copy.deepcopy(assurance.read_policy())
    policy["harness"]["shell_execution"] = True
    with fails_with("security controls were weakened"):
        assurance.validate_policy(policy)


def test_duplicate_target_fails() -> None:
    policy = copy.deepcopy(assurance.read_policy())
    policy["bare_metal_targets"][1] = copy.deepcopy(
        policy["bare_metal_targets"][0]
    )
    with fails_with("matrix is incomplete or duplicated"):
        assurance.validate_policy(policy)


def test_single_differential_implementation_fails() -> None:
    policy = copy.deepcopy(assurance.read_policy())
    policy["differential"]["minimum_independent_implementations"] = 1
    with fails_with("differential contract drifted"):
        assurance.validate_policy(policy)


def test_unpinned_tool_fails() -> None:
    policy = copy.deepcopy(assurance.read_policy())
    policy["tools"][0]["revision"] = "main"
    with fails_with("revision is not an exact commit"):
        assurance.validate_policy(policy)


def test_kani_toolchain_separation_fails_closed() -> None:
    policy = copy.deepcopy(assurance.read_policy())
    kani = next(tool for tool in policy["tools"] if tool["id"] == "kani")
    kani["execution_toolchain"] = "1.97.1"
    with fails_with("Kani execution toolchain drifted"):
        assurance.validate_policy(policy)


def test_missing_ci_target_fails() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    broken = workflow.replace("          - x86_64-unknown-none\n", "")
    with fails_with("CI must contain bare-metal target exactly once"):
        assurance.validate_workflow(broken)


def test_tool_in_cargo_manifest_fails() -> None:
    tools = assurance.read_policy()["tools"]
    with fails_with("assurance tool entered Cargo manifest: kani"):
        assurance.validate_manifest_text(
            '[dependencies]\nkani-verifier = "0.67.0"\n',
            tools,
            "fixture/Cargo.toml",
        )


def test_rust_target_probe_is_time_bounded() -> None:
    targets = "\n".join(assurance.TARGETS)
    with mock.patch.object(
        assurance.subprocess, "check_output", return_value=targets
    ) as check:
        assurance.validate_repository(assurance.read_policy())
    assert check.call_args.kwargs["timeout"] == (
        assurance.SUBPROCESS_TIMEOUT_SECONDS
    )


def test_upstream_tag_probe_is_time_bounded() -> None:
    policy = copy.deepcopy(assurance.read_policy())
    tool = next(item for item in policy["tools"] if item["id"] == "kani")
    policy["tools"] = [tool]
    output = f"{tool['revision']}\trefs/tags/{tool['tag']}\n"
    with mock.patch.object(
        assurance.subprocess, "check_output", return_value=output
    ) as check:
        assurance.network_check(policy)
    assert check.call_args.kwargs["timeout"] == (
        assurance.SUBPROCESS_TIMEOUT_SECONDS
    )


def test_mutations_are_deterministic_and_cover_boundaries() -> None:
    first = mutation.mutations(b"\x00\xff", 100, 100)
    second = mutation.mutations(b"\x00\xff", 100, 100)
    assert first == second
    assert first[0] == b""
    assert b"\x00\xff" in first
    assert b"\xff" in first
    assert len(first) == len(set(first))


def test_mutations_stop_at_case_bound() -> None:
    assert len(mutation.mutations(bytes(range(64)), 7, 64)) == 7


def test_mutations_never_exceed_input_bound() -> None:
    cases = mutation.mutations(b"\x00\xff", 100, 2)
    assert all(len(case) <= 2 for case in cases)


def test_canonical_result_parses() -> None:
    raw = b'{"class":"accept","output":"00ff"}'
    assert differential.parse_result(raw) == {
        "class": "accept",
        "output": "00ff",
    }


def test_noncanonical_result_fails() -> None:
    raw = json.dumps({"output": "00", "class": "accept"}).encode()
    with fails_with("not canonical JSON"):
        differential.parse_result(raw)


def test_result_whitespace_fails() -> None:
    with fails_with("not canonical JSON"):
        differential.parse_result(b'{"class":"accept","output":""}\n')


def test_noncanonical_hex_fails() -> None:
    with fails_with("not canonical lowercase hex"):
        differential.parse_result(b'{"class":"accept","output":"AA"}')


def test_unknown_result_field_fails() -> None:
    with fails_with("fields drifted"):
        differential.parse_result(
            b'{"class":"accept","extra":false,"output":""}'
        )


def test_differential_agreement_passes() -> None:
    count = differential.compare(
        [command("echo"), command("echo-alt")],
        [b"", b"\x00\xff"],
        1,
        1024,
    )
    assert count == 2


def test_duplicate_adapter_fails() -> None:
    with fails_with("two distinct adapters"):
        differential.compare([command("echo"), command("echo")], [b""], 1, 1024)


def test_empty_differential_corpus_fails() -> None:
    with fails_with("at least one case"):
        differential.compare(
            [command("echo"), command("echo-alt")], [], 1, 1024
        )


def test_differential_mismatch_fails() -> None:
    with fails_with("differential mismatch"):
        differential.compare(
            [command("echo"), command("diverge")],
            [b"case"],
            1,
            1024,
        )


def test_adapter_failure_fails() -> None:
    with fails_with("adapter failed"):
        differential.run_adapter(command("fail"), b"", 1, 1024)


def test_process_timeout_fails() -> None:
    with fails_with("timed out"):
        run_bounded(command("hang"), b"", 0.05, 1024)


def test_process_output_bound_fails() -> None:
    with fails_with("exceeded output bound"):
        run_bounded(command("flood"), b"", 1, 64)


def test_release_version_ordering() -> None:
    assert assurance.version_key("0.67.0") > assurance.version_key("0.9.0")
    assert assurance.version_key("5.02c") > assurance.version_key("4.40c")


def main() -> int:
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"{len(tests)} assurance policy and harness tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
