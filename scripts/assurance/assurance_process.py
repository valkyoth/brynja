#!/usr/bin/env python3
"""Cross-platform bounded child-process execution for assurance runners."""

from __future__ import annotations

import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import BinaryIO

from assurance_process_tree import (
    ProcessTree,
    popen_tree_options,
    validate_tree_containment,
)


CLEANUP_WAIT_SECONDS = 1.0


def _cleanup_failure(
    detail: str, timed_out: bool, overflow: threading.Event,
) -> RuntimeError:
    """Keep the execution failure visible without hiding failed cleanup."""
    causes = []
    if timed_out:
        causes.append("assurance process timed out")
    if overflow.is_set():
        causes.append("assurance process exceeded output bound")
    causes.append(detail)
    return RuntimeError("; ".join(causes))


@dataclass(frozen=True)
class ProcessResult:
    """Bounded process result."""

    returncode: int
    stdout: bytes
    stderr: bytes


def _read_bounded(
    stream: BinaryIO,
    maximum: int,
    output: list[bytes],
    overflow: threading.Event,
    tree: ProcessTree,
) -> None:
    chunks = bytearray()
    try:
        while True:
            chunk = stream.read(min(65_536, maximum + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > maximum:
                overflow.set()
                tree.kill()
                break
    except (OSError, ValueError):
        pass
    finally:
        output.append(bytes(chunks[:maximum]))


def run_bounded(
    command: list[str],
    payload: bytes,
    timeout_seconds: float,
    maximum_output: int,
    tree_containment: str | None,
    *,
    allow_test_only_containment: bool = False,
) -> ProcessResult:
    """Run without a shell and cap each output stream while it is produced."""
    if not command:
        raise RuntimeError("assurance command is empty")
    if timeout_seconds <= 0 or maximum_output < 0:
        raise RuntimeError("assurance process bounds are invalid")
    validate_tree_containment(
        tree_containment,
        allow_test_only=allow_test_only_containment,
    )
    with tempfile.TemporaryFile() as input_file:
        input_file.write(payload)
        input_file.seek(0)
        process = subprocess.Popen(
            command,
            stdin=input_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            **popen_tree_options(),
        )
        tree = ProcessTree(process)
        if process.stdout is None or process.stderr is None:
            tree.kill()
            tree.close()
            raise RuntimeError("assurance process pipes are unavailable")
        overflow = threading.Event()
        stdout: list[bytes] = []
        stderr: list[bytes] = []
        threads = [
            threading.Thread(
                target=_read_bounded,
                args=(process.stdout, maximum_output, stdout, overflow, tree),
                daemon=True,
            ),
            threading.Thread(
                target=_read_bounded,
                args=(process.stderr, maximum_output, stderr, overflow, tree),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        timed_out = False
        deadline = time.monotonic() + timeout_seconds
        try:
            try:
                remaining = max(0.0, deadline - time.monotonic())
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                returncode = -1
            finally:
                tree.kill()
            try:
                process.wait(timeout=CLEANUP_WAIT_SECONDS)
            except subprocess.TimeoutExpired as error:
                raise _cleanup_failure(
                    "assurance process tree would not terminate", timed_out, overflow,
                ) from error
            for thread in threads:
                thread.join(timeout=CLEANUP_WAIT_SECONDS)
            if any(thread.is_alive() for thread in threads):
                raise _cleanup_failure(
                    "assurance process tree kept an output stream open", timed_out, overflow,
                )
            if timed_out:
                raise RuntimeError("assurance process timed out")
            if overflow.is_set():
                raise RuntimeError("assurance process exceeded output bound")
            if len(stdout) != 1 or len(stderr) != 1:
                raise RuntimeError("assurance process output collection failed")
            return ProcessResult(returncode, stdout[0], stderr[0])
        finally:
            tree.kill()
            for thread in threads:
                thread.join(timeout=CLEANUP_WAIT_SECONDS)
            if not any(thread.is_alive() for thread in threads):
                process.stdout.close()
                process.stderr.close()
            tree.close()
