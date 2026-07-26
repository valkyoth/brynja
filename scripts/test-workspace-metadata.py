#!/usr/bin/env python3
"""Exercise negative fixtures for package-name and TLS graph isolation."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path


VALIDATOR = Path(__file__).with_name("validate-workspace-metadata.py")


def package_id(document: dict, name: str) -> str:
    return next(package["id"] for package in document["packages"] if package["name"] == name)


def node(document: dict, name: str) -> dict:
    identifier = package_id(document, name)
    return next(item for item in document["resolve"]["nodes"] if item["id"] == identifier)


def validator_result(document: dict) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as fixture:
        json.dump(document, fixture)
        fixture.flush()
        return subprocess.run(
            [sys.executable, str(VALIDATOR), fixture.name],
            check=False,
            capture_output=True,
            text=True,
        )


def require_rejection(document: dict, label: str) -> None:
    result = validator_result(document)
    if result.returncode == 0:
        raise AssertionError(f"workspace validator accepted {label}")


def main() -> int:
    baseline = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1"],
            text=True,
        )
    )
    accepted = validator_result(baseline)
    if accepted.returncode != 0:
        raise AssertionError(f"workspace validator rejected baseline: {accepted.stderr}")

    ambiguous_name = copy.deepcopy(baseline)
    legacy = next(
        package
        for package in ambiguous_name["packages"]
        if package["name"] == "brynja-legacy-ssl2"
    )
    legacy["name"] = "brynja-ssl2"
    require_rejection(ambiguous_name, "an ambiguously named legacy crate")

    deprecated_name = copy.deepcopy(baseline)
    legacy = next(
        package
        for package in deprecated_name["packages"]
        if package["name"] == "brynja-legacy-ssl2"
    )
    legacy["name"] = "brynja-historical-ssl2"
    require_rejection(deprecated_name, "the deprecated historical prefix")

    modern_leak = copy.deepcopy(baseline)
    node(modern_leak, "brynja")["deps"].append(
        {"pkg": package_id(modern_leak, "brynja-legacy-ssl2")}
    )
    require_rejection(modern_leak, "a modern-to-legacy dependency")

    research_leak = copy.deepcopy(baseline)
    node(research_leak, "brynja")["deps"].append(
        {"pkg": package_id(research_leak, "brynja-research-ssl1")}
    )
    require_rejection(research_leak, "a modern-to-research dependency")

    published_research = copy.deepcopy(baseline)
    research = next(
        package
        for package in published_research["packages"]
        if package["name"] == "brynja-research-ssl1"
    )
    research["publish"] = None
    require_rejection(published_research, "a publishable research crate")

    missing_engine = copy.deepcopy(baseline)
    tls12 = package_id(missing_engine, "brynja-tls12")
    router = node(missing_engine, "brynja-tls")
    router["deps"] = [dependency for dependency in router["deps"] if dependency["pkg"] != tls12]
    require_rejection(missing_engine, "an evergreen router without TLS 1.2")

    quic_stream_leak = copy.deepcopy(baseline)
    node(quic_stream_leak, "brynja-quic-tls")["deps"].append(
        {"pkg": package_id(quic_stream_leak, "brynja-tls13")}
    )
    require_rejection(quic_stream_leak, "a QUIC-to-stream-TLS dependency")

    print("workspace metadata validator rejects package and TLS graph regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
