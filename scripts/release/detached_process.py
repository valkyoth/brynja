"""Bounded POSIX command execution for trusted repository verification.

Process groups contain cooperative Cargo/test children, not hostile processes
which call setsid or escape their session. Use a dedicated VM/container for
untrusted code. This runner is not an adversarial process sandbox.
"""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from pathlib import Path


def kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def execute(argv: list[str], root: Path, log: Path, cancel: Path, *,
            seconds: float, maximum: int, environment: dict[str, str],
            stdin: str | None = None) -> dict:
    if os.name != "posix" or seconds <= 0 or maximum < 1:
        raise ValueError("unsupported platform or invalid process bounds")
    started = time.monotonic()
    status, count = "failed", 0
    source = (root / stdin).open("rb") if stdin else None
    process = None
    killed = False
    try:
        with log.open("xb") as stream, selectors.DefaultSelector() as selector:
            os.chmod(log, 0o600)
            process = subprocess.Popen(argv, cwd=root, env=environment,
                                       stdin=source or subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=True, close_fds=True)
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                if cancel.exists():
                    status = "cancelled"
                    break
                if time.monotonic() - started >= seconds:
                    status = "timed_out"
                    break
                events = selector.select(min(0.1, max(0, seconds - (time.monotonic() - started))))
                for key, _ in events:
                    chunk = os.read(key.fd, min(65536, maximum - count + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        allowed = chunk[:maximum - count]
                        stream.write(allowed)
                        count += len(allowed)
                        if len(chunk) > len(allowed):
                            status = "log_limit"
                            break
                if status == "log_limit":
                    break
                if not selector.get_map() and process.poll() is not None:
                    status = "passed" if process.returncode == 0 else "failed"
                    break
            # Always retire inherited descendants, even when the leader exited.
            kill_group(process)
            killed = True
            process.wait(timeout=5)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if process is not None:
            if not killed:
                kill_group(process)
            process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
        if source is not None:
            source.close()
    return {"state": status, "exit_code": process.returncode,
            "elapsed_seconds": time.monotonic() - started, "log_bytes": count}
