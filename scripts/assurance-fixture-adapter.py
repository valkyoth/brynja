#!/usr/bin/env python3
"""Test-only adapter for the first-party assurance harness."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


DESCENDANT = (
    "descendant-hold",
    "descendant-timeout",
    "descendant-flood",
    "descendant-marker",
    "descendant-detached-marker",
)


def spawn_descendant(mode: str, marker: str | None) -> None:
    if mode == "descendant-flood":
        code = (
            "import sys,time;"
            "sys.stdout.write('x'*4096);sys.stdout.flush();time.sleep(2)"
        )
        arguments = [sys.executable, "-c", code]
    elif mode in ("descendant-marker", "descendant-detached-marker"):
        if marker is None:
            raise RuntimeError("descendant marker path is required")
        marker_path = str(Path(marker))
        if mode == "descendant-detached-marker":
            release_path = f"{marker_path}.release"
            code = "\n".join(
                (
                    "import pathlib, sys, time",
                    "release = pathlib.Path(sys.argv[1])",
                    "marker = pathlib.Path(sys.argv[2])",
                    "deadline = time.monotonic() + 10",
                    "while not release.exists() and time.monotonic() < deadline:",
                    "    time.sleep(0.01)",
                    "if release.exists():",
                    "    marker.write_text('escaped')",
                )
            )
            arguments = [
                sys.executable,
                "-c",
                code,
                release_path,
                marker_path,
            ]
        else:
            code = (
                "import pathlib,sys,time;"
                "time.sleep(0.3);pathlib.Path(sys.argv[1]).write_text('escaped')"
            )
            arguments = [sys.executable, "-c", code, marker_path]
    else:
        arguments = [sys.executable, "-c", "import time;time.sleep(2)"]
    detached = mode == "descendant-detached-marker"
    subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL if detached else None,
        stdout=subprocess.DEVNULL if detached else None,
        stderr=subprocess.DEVNULL if detached else None,
        shell=False,
        start_new_session=detached,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=(
            "echo",
            "echo-alt",
            "reject",
            "diverge",
            "fail",
            "hang",
            "flood",
            *DESCENDANT,
        ),
    )
    parser.add_argument("marker", nargs="?")
    args = parser.parse_args()
    payload = sys.stdin.buffer.read()
    if args.mode == "fail":
        return 1
    if args.mode == "hang":
        time.sleep(2)
    if args.mode == "flood":
        sys.stdout.write("x" * 4096)
        return 0
    if args.mode in DESCENDANT:
        spawn_descendant(args.mode, args.marker)
        if args.mode in (
            "descendant-hold",
            "descendant-marker",
            "descendant-detached-marker",
        ):
            return 0
        time.sleep(2)
        return 0
    output = payload.hex()
    result_class = "accept"
    if args.mode == "reject":
        result_class = "reject"
        output = ""
    elif args.mode == "diverge":
        output += "00"
    sys.stdout.write(
        json.dumps(
            {"class": result_class, "output": output},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
