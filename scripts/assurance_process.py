#!/usr/bin/env python3
"""Cross-platform bounded child-process execution for assurance runners."""

from __future__ import annotations

import subprocess
import tempfile
import threading
from dataclasses import dataclass
from typing import BinaryIO


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
    process: subprocess.Popen[bytes],
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
                process.kill()
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
) -> ProcessResult:
    """Run without a shell and cap each output stream while it is produced."""
    if not command:
        raise RuntimeError("assurance command is empty")
    with tempfile.TemporaryFile() as input_file:
        input_file.write(payload)
        input_file.seek(0)
        process = subprocess.Popen(
            command,
            stdin=input_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        if process.stdout is None or process.stderr is None:
            process.kill()
            raise RuntimeError("assurance process pipes are unavailable")
        overflow = threading.Event()
        stdout: list[bytes] = []
        stderr: list[bytes] = []
        threads = [
            threading.Thread(
                target=_read_bounded,
                args=(process.stdout, maximum_output, stdout, overflow, process),
                daemon=True,
            ),
            threading.Thread(
                target=_read_bounded,
                args=(process.stderr, maximum_output, stderr, overflow, process),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            process.stdout.close()
            process.stderr.close()
            for thread in threads:
                thread.join(timeout=1)
            raise RuntimeError("assurance process timed out") from error
        for thread in threads:
            thread.join(timeout=1)
        if any(thread.is_alive() for thread in threads):
            process.stdout.close()
            process.stderr.close()
            raise RuntimeError("assurance process kept an output stream open")
        if overflow.is_set():
            raise RuntimeError("assurance process exceeded output bound")
        if len(stdout) != 1 or len(stderr) != 1:
            raise RuntimeError("assurance process output collection failed")
        return ProcessResult(returncode, stdout[0], stderr[0])
