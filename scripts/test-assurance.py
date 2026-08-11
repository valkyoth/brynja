#!/usr/bin/env python3
"""Positive and broken fixtures for the v0.4.0 assurance boundary."""

from __future__ import annotations

import copy
import itertools
import json
import os
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import assurance_differential as differential
import assurance_io
import assurance_mutation as mutation
import assurance_policy as assurance
import assurance_process_tests
import assurance_process_tree as process_tree
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


def command(mode: str, *arguments: str) -> list[str]:
    return [sys.executable, str(ADAPTER), mode, *arguments]


def fixture_containment() -> str | None:
    if os.name == "nt":
        return None
    return process_tree.TEST_ONLY_POSIX_GROUP


def run_fixture(
    mode: str,
    timeout_seconds: float,
    maximum_output: int,
    *arguments: str,
):
    return run_bounded(
        command(mode, *arguments),
        b"",
        timeout_seconds,
        maximum_output,
        fixture_containment(),
        allow_test_only_containment=True,
    )


def compare_fixture(
    commands: list[list[str]],
    cases,
    timeout_seconds: float,
    maximum_output: int,
) -> int:
    return differential.compare(
        commands,
        cases,
        timeout_seconds,
        maximum_output,
        fixture_containment(),
        allow_test_only_containment=True,
    )


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


def test_process_tree_policy_drift_fails() -> None:
    policy = copy.deepcopy(assurance.read_policy())
    policy["harness"]["process_tree_termination"] = "immediate-child-only"
    with fails_with("security controls were weakened"):
        assurance.validate_policy(policy)


def test_missing_native_assurance_ci_fails() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    broken = workflow.replace(
        "      - name: Test assurance platform boundary\n"
        "        run: python scripts/test-assurance.py\n",
        "",
    )
    with fails_with("native host assurance test command drifted"):
        assurance.validate_workflow(broken)


def test_corpus_input_policy_drift_fails() -> None:
    policy = copy.deepcopy(assurance.read_policy())
    policy["harness"]["corpus_input"] = "read-whole-corpus"
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


def test_missing_repository_gate_target_install_fails() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    install = "        run: rustup target add " + " ".join(assurance.TARGETS) + "\n"
    broken = workflow.replace(install, "")
    with fails_with("CI bare-metal target installation drifted"):
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


def test_streamed_mutations_match_exact_deduplicated_order() -> None:
    def reference(seed: bytes) -> list[bytes]:
        candidates = [b"", seed]
        candidates.extend(seed[:end] for end in range(len(seed)))
        candidates.extend(
            seed[:offset] + seed[offset + 1 :] for offset in range(len(seed))
        )
        candidates.extend(
            seed[:offset]
            + bytes([value ^ (1 << bit)])
            + seed[offset + 1 :]
            for offset, value in enumerate(seed)
            for bit in range(8)
        )
        candidates.extend(
            seed[:offset] + inserted + seed[offset:]
            for inserted in (b"\x00", b"\xff")
            for offset in range(len(seed) + 1)
        )
        return list(dict.fromkeys(candidates))

    for length in range(5):
        for values in itertools.product((0x00, 0x01, 0xFF), repeat=length):
            seed = bytes(values)
            assert list(mutation.mutation_cases(seed, 10_000, 16)) == reference(
                seed
            )


def test_bounded_file_read_uses_limit_plus_one() -> None:
    handle = mock.MagicMock()
    handle.__enter__.return_value = handle
    handle.fileno.return_value = 7
    handle.read.return_value = b"bounded"
    metadata = mock.Mock(st_mode=stat.S_IFREG, st_size=7)
    with (
        mock.patch.object(assurance_io, "_open_regular", return_value=handle),
        mock.patch.object(assurance_io.os, "fstat", return_value=metadata),
    ):
        assert assurance_io.read_bounded_regular(Path("case"), 8) == b"bounded"
    handle.read.assert_called_once_with(9)


def test_oversized_file_fails_before_read() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "oversized"
        path.write_bytes(b"x" * 65)
        with fails_with("exceeds policy input bound"):
            assurance_io.read_bounded_regular(path, 64)


def test_symlink_case_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "target"
        link = Path(directory) / "link"
        target.write_bytes(b"case")
        try:
            link.symlink_to(target)
        except OSError:
            return
        with fails_with("securely open"):
            assurance_io.read_bounded_regular(link, 64)


def test_corpus_count_is_bounded_during_enumeration() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for index in range(3):
            (root / str(index)).write_bytes(b"case")
        with fails_with("corpus exceeds policy bound"):
            list(assurance_io.iter_bounded_corpus(root, 2, 64))


def test_symlink_corpus_directory_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        corpus = root / "corpus"
        link = root / "link"
        corpus.mkdir()
        (corpus / "case").write_bytes(b"case")
        try:
            link.symlink_to(corpus, target_is_directory=True)
        except OSError:
            return
        try:
            list(assurance_io.iter_bounded_corpus(link, 2, 64))
        except RuntimeError:
            return
        raise AssertionError("symlink corpus unexpectedly passed")


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
    count = compare_fixture(
        [command("echo"), command("echo-alt")],
        [b"", b"\x00\xff"],
        1,
        1024,
    )
    assert count == 2


def test_differential_cases_are_consumed_one_at_a_time() -> None:
    events: list[str] = []

    def cases():
        events.append("load-1")
        yield b"one"
        events.append("load-2")
        yield b"two"

    def adapter(
        _command,
        case,
        _timeout,
        _maximum,
        _containment,
        *,
        allow_test_only_containment,
    ):
        assert allow_test_only_containment
        events.append(f"run-{case.decode()}")
        return {"class": "accept", "output": case.hex()}

    with mock.patch.object(differential, "run_adapter", side_effect=adapter):
        assert compare_fixture(
            [["first"], ["second"]],
            cases(),
            1,
            64,
        ) == 2
    assert events == [
        "load-1",
        "run-one",
        "run-one",
        "load-2",
        "run-two",
        "run-two",
    ]


def test_duplicate_adapter_fails() -> None:
    with fails_with("two distinct adapters"):
        compare_fixture([command("echo"), command("echo")], [b""], 1, 1024)


def test_empty_differential_corpus_fails() -> None:
    with fails_with("at least one case"):
        compare_fixture(
            [command("echo"), command("echo-alt")], [], 1, 1024
        )


def test_differential_mismatch_fails() -> None:
    with fails_with("differential mismatch"):
        compare_fixture(
            [command("echo"), command("diverge")],
            [b"case"],
            1,
            1024,
        )


def test_adapter_failure_fails() -> None:
    with fails_with("adapter failed"):
        differential.run_adapter(
            command("fail"),
            b"",
            1,
            1024,
            fixture_containment(),
            allow_test_only_containment=True,
        )


def test_release_version_ordering() -> None:
    assert assurance.version_key("0.67.0") > assurance.version_key("0.9.0")
    assert assurance.version_key("5.02c") > assurance.version_key("4.40c")


def main() -> int:
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    tests.extend(assurance_process_tests.tests())
    for test in tests:
        test()
    print(f"{len(tests)} assurance policy and harness tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
