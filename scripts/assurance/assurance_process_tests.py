"""Native-host process-containment regressions for the assurance harness."""

from __future__ import annotations

import math
import os
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

import assurance_process as process_runner
import assurance_process_tree as process_tree
from assurance_process import run_bounded


ROOT = Path(__file__).resolve().parent.parent.parent
ADAPTER = ROOT / "scripts" / "assurance" / "assurance-fixture-adapter.py"


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


def wait_for_path(path: Path, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.01)
    return path.exists()


def test_path_wait_has_a_bounded_failure() -> None:
    with tempfile.TemporaryDirectory() as directory:
        missing = Path(directory) / "missing"
        started = time.monotonic()
        assert not wait_for_path(missing, 0.05)
        assert time.monotonic() - started < 1


def test_process_timeout_fails() -> None:
    with fails_with("timed out"):
        run_fixture("hang", 0.05, 1024)


def test_process_output_bound_fails() -> None:
    with fails_with("exceeded output bound"):
        run_fixture("flood", 1, 64)


def test_process_tree_platform_isolation_is_enabled() -> None:
    options = process_tree.popen_tree_options()
    if os.name == "nt":
        flags = options["creationflags"]
        assert isinstance(flags, int)
        assert flags & process_tree.CREATE_SUSPENDED
        assert process_tree.CREATE_SUSPENDED == 0x00000004
    else:
        assert options == {"start_new_session": True}


def test_hostile_posix_requires_external_containment() -> None:
    if os.name == "nt":
        assert (
            process_tree.validate_tree_containment(None)
            == process_tree.WINDOWS_JOB_OBJECT
        )
        with fails_with("Windows adapters require"):
            process_tree.validate_tree_containment("container-vm")
        return
    with fails_with("requires externally enforced"):
        process_tree.validate_tree_containment(None)
    with fails_with("requires externally enforced"):
        process_tree.validate_tree_containment(process_tree.TEST_ONLY_POSIX_GROUP)
    assert process_tree.validate_tree_containment("container-vm") == "container-vm"
    assert (
        process_tree.validate_tree_containment(
            process_tree.TEST_ONLY_POSIX_GROUP,
            allow_test_only=True,
        )
        == process_tree.TEST_ONLY_POSIX_GROUP
    )


def test_parent_exit_with_descendant_pipe_is_bounded() -> None:
    started = time.monotonic()
    result = run_fixture("descendant-hold", 0.2, 1024)
    assert result.returncode == 0
    assert_cleanup_bounded(started, 0.2)


def test_descendant_timeout_is_bounded() -> None:
    started = time.monotonic()
    with fails_with("timed out"):
        run_fixture("descendant-timeout", 0.05, 1024)
    assert_cleanup_bounded(started, 0.05)


def test_descendant_output_is_bounded() -> None:
    started = time.monotonic()
    with fails_with("exceeded output bound"):
        run_fixture("descendant-flood", 1, 64)
    assert_cleanup_bounded(started, 1)


def assert_cleanup_bounded(started: float, execution_timeout: float) -> None:
    # One reap wait, two initial reader joins, two final reader joins. Startup
    # and CI scheduling get modest slack; execution and cleanup stay bounded.
    maximum = execution_timeout + 5 * process_runner.CLEANUP_WAIT_SECONDS + 2
    assert time.monotonic() - started < maximum


def check_cleanup_failure(
    timed_out: bool,
    overflow: bool,
    reap_fails: bool,
    clock_readings: tuple[float, float] = (0.0, 0.0),
) -> None:
    process = Mock()
    process.wait.side_effect = [
        subprocess.TimeoutExpired("fixture", 0.05) if timed_out else 0,
        subprocess.TimeoutExpired("fixture", 1) if reap_fails else 0,
    ]
    tree = Mock()
    readers = [Mock(), Mock()]
    for reader in readers:
        reader.is_alive.return_value = not reap_fails
    overflow_event = Mock()
    overflow_event.is_set.return_value = overflow
    causes = []
    if timed_out:
        causes.append("assurance process timed out")
    if overflow:
        causes.append("assurance process exceeded output bound")
    causes.append(
        "assurance process tree would not terminate" if reap_fails else
        "assurance process tree kept an output stream open"
    )
    # Deterministically reproduce delayed pipe EOF/reaping on any host. The
    # fake readers start no threads and the fake process launches no child.
    with (
        patch.object(process_runner.subprocess, "Popen", return_value=process),
        patch.object(process_runner, "ProcessTree", return_value=tree),
        patch.object(process_runner.threading, "Thread", side_effect=readers),
        patch.object(process_runner.threading, "Event", return_value=overflow_event),
        patch.object(process_runner.time, "monotonic", side_effect=clock_readings),
    ):
        try:
            run_fixture("descendant-timeout", 0.05, 1024)
        except RuntimeError as error:
            assert str(error) == "; ".join(causes), str(error)
            if reap_fails:
                assert isinstance(error.__cause__, subprocess.TimeoutExpired)
        else:
            raise AssertionError("cleanup failure must never return success")
    assert tree.kill.call_count == 2
    tree.close.assert_called_once_with()
    assert process.wait.call_count == 2
    first_wait, reap_wait = process.wait.call_args_list
    deadline = clock_readings[0] + 0.05
    remaining = first_wait.kwargs["timeout"]
    assert remaining == max(0.0, deadline - clock_readings[1])
    # Equal clock ticks can expose rounding when adding a short timeout to a
    # large clock origin. Allow one representable deadline step, not CI slack.
    assert 0 <= remaining <= 0.05 + math.ulp(deadline)
    assert reap_wait.kwargs == {"timeout": process_runner.CLEANUP_WAIT_SECONDS}
    for reader in readers:
        reader.start.assert_called_once_with()
        assert reader.join.call_count == (1 if reap_fails else 2)
        assert all(
            call.kwargs == {"timeout": process_runner.CLEANUP_WAIT_SECONDS}
            for call in reader.join.call_args_list
        )
    for pipe in (process.stdout, process.stderr):
        if reap_fails:
            pipe.close.assert_called_once_with()
        else:
            # Closing a buffered stream still held by a reader can block.
            pipe.close.assert_not_called()


def test_cleanup_retains_timeout_overflow_and_containment_failures() -> None:
    for timed_out in (False, True):
        for overflow in (False, True):
            for reap_fails in (False, True):
                check_cleanup_failure(timed_out, overflow, reap_fails)


def test_cleanup_deadline_handles_clock_rounding_and_expiry() -> None:
    origin = 1_000_000.0
    assert (origin + 0.05) - origin > 0.05  # Reproduce the former strict-bound failure.
    for elapsed in (0.0, 0.025, 0.05, 0.1):
        for timed_out in (False, True):
            for overflow in (False, True):
                for reap_fails in (False, True):
                    check_cleanup_failure(
                        timed_out, overflow, reap_fails, (origin, origin + elapsed),
                    )


def test_cooperative_descendant_cannot_survive_termination() -> None:
    with tempfile.TemporaryDirectory() as directory:
        marker = Path(directory) / "escaped"
        result = run_fixture("descendant-marker", 5, 1024, str(marker))
        assert result.returncode == 0
        time.sleep(0.5)
        assert not marker.exists()


def test_detached_posix_descendant_is_not_claimed_as_contained() -> None:
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as directory:
        marker = Path(directory) / "detached"
        release = Path(f"{marker}.release")
        result = run_fixture(
            "descendant-detached-marker",
            5,
            1024,
            str(marker),
        )
        assert result.returncode == 0
        assert not marker.exists()
        release.write_text("release")
        assert wait_for_path(marker, 5)


def tests() -> list:
    return [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
