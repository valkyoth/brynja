"""Native-host process-containment regressions for the assurance harness."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

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
    assert time.monotonic() - started < 1


def test_descendant_timeout_is_bounded() -> None:
    started = time.monotonic()
    with fails_with("timed out"):
        run_fixture("descendant-timeout", 0.05, 1024)
    assert time.monotonic() - started < 1


def test_descendant_output_is_bounded() -> None:
    started = time.monotonic()
    with fails_with("exceeded output bound"):
        run_fixture("descendant-flood", 1, 64)
    assert time.monotonic() - started < 1


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
