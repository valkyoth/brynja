#!/usr/bin/env python3
"""Validate and render Brynja's v0.4.0 assurance policy."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "assurance" / "policy.toml"
EVIDENCE = ROOT / "assurance" / "evidence.json"
TARGETS = (
    "riscv32imac-unknown-none-elf",
    "thumbv7em-none-eabi",
    "x86_64-unknown-none",
)
TOOL_IDS = ("aflplusplus", "honggfuzz", "kani", "miri", "rust-sanitizers")
SUBPROCESS_TIMEOUT_SECONDS = 30
TOOL_MANIFEST_TOKENS = {
    "aflplusplus": ("afl", "aflplusplus"),
    "honggfuzz": ("honggfuzz",),
    "kani": ("kani", "kani-verifier"),
    "miri": ("miri",),
    "rust-sanitizers": ("sanitizer",),
}
SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)*(?:[a-z])?$")
NIGHTLY = re.compile(r"^nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def fail(message: str) -> None:
    raise RuntimeError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        fail(f"assurance input must be a regular file: {path.relative_to(ROOT)}")
    return sha256(path.read_bytes())


def read_policy(path: Path = POLICY) -> dict:
    with path.open("rb") as handle:
        policy = tomllib.load(handle)
    validate_policy(policy)
    return policy


def exact_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} fields drifted")


def validate_policy(policy: dict) -> None:
    exact_keys(
        policy,
        {
            "schema",
            "toolchains",
            "harness",
            "mutation",
            "differential",
            "bare_metal_targets",
            "tools",
        },
        "assurance policy",
    )
    if policy["schema"] != {"version": 1, "milestone": "0.4.0"}:
        fail("assurance schema or milestone drifted")
    validate_toolchains(policy["toolchains"])
    validate_harness(policy["harness"])
    validate_mutation(policy["mutation"])
    validate_differential(policy["differential"])
    validate_targets(policy["bare_metal_targets"])
    validate_tools(policy["tools"])


def validate_toolchains(toolchains: dict) -> None:
    if (
        set(toolchains) != {"release", "msrv", "kani"}
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchains["release"]) is None
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchains["msrv"]) is None
        or toolchains["kani"] != "1.90.0-x86_64-unknown-linux-gnu"
    ):
        fail("stable release, MSRV, or Kani toolchain boundary drifted")


def validate_harness(harness: dict) -> None:
    exact_keys(
        harness,
        {
            "protocol",
            "maximum_input_bytes",
            "maximum_output_bytes",
            "maximum_cases",
            "timeout_milliseconds",
            "shell_execution",
            "deterministic_replay",
            "network_isolation",
            "input_class",
            "automatic_failure_persistence",
            "process_tree_termination",
            "corpus_input",
        },
        "harness",
    )
    if harness["protocol"] != "brynja-stdin-json-v1":
        fail("harness protocol drifted")
    for field, lower, upper in (
        ("maximum_input_bytes", 1, 16_777_216),
        ("maximum_output_bytes", 1, 16_777_216),
        ("maximum_cases", 1, 65_536),
        ("timeout_milliseconds", 1, 60_000),
    ):
        value = harness[field]
        if not isinstance(value, int) or not lower <= value <= upper:
            fail(f"harness {field} is unbounded or invalid")
    if (
        harness["shell_execution"]
        or not harness["deterministic_replay"]
        or harness["automatic_failure_persistence"]
        or harness["network_isolation"] != "external-sandbox-required"
        or harness["input_class"] != "public-test-data-only"
        or harness["process_tree_termination"]
        != "hostile-posix-external-containment-windows-job"
        or harness["corpus_input"]
        != "descriptor-bound-no-follow-limit-plus-one-streaming"
    ):
        fail("harness security controls were weakened")


def validate_mutation(mutation: dict) -> None:
    exact_keys(mutation, {"runner", "algorithm", "operators"}, "mutation")
    expected = [
        "empty",
        "original",
        "truncate",
        "delete-byte",
        "flip-bit",
        "insert-zero",
        "insert-ff",
    ]
    if (
        mutation["runner"] != "scripts/assurance_mutation.py"
        or mutation["algorithm"] != "brynja-deterministic-mutation-v1"
        or mutation["operators"] != expected
    ):
        fail("mutation contract drifted")


def validate_differential(differential: dict) -> None:
    exact_keys(
        differential,
        {
            "runner",
            "minimum_independent_implementations",
            "result_fields",
            "result_classes",
            "canonical_json",
        },
        "differential",
    )
    if (
        differential["runner"] != "scripts/assurance_differential.py"
        or differential["minimum_independent_implementations"] < 2
        or differential["result_fields"] != ["class", "output"]
        or differential["result_classes"]
        != ["accept", "reject", "unsupported"]
        or differential["canonical_json"] is not True
    ):
        fail("differential contract drifted")


def validate_targets(targets: list[dict]) -> None:
    triples = []
    for target in targets:
        exact_keys(
            target,
            {"triple", "architecture", "class", "features"},
            "bare-metal target",
        )
        if (
            target["class"] != "os-less"
            or target["features"] != "all"
            or not target["architecture"]
        ):
            fail("bare-metal target boundary drifted")
        triples.append(target["triple"])
    if tuple(sorted(triples)) != TARGETS or len(set(triples)) != len(triples):
        fail("bare-metal target matrix is incomplete or duplicated")


def validate_tools(tools: list[dict]) -> None:
    ids = []
    versions = set()
    for tool in tools:
        exact_keys(
            tool,
            {
                "id",
                "source_kind",
                "source",
                "version",
                "tag",
                "revision",
                "owner",
                "use",
                "execution_toolchain",
            },
            "assurance tool",
        )
        ids.append(tool["id"])
        if tool["source_kind"] not in {
            "git-tag",
            "rust-toolchain",
            "rustup-component",
        }:
            fail(f"{tool['id']} has unknown source kind")
        if not tool["source"].startswith("https://"):
            fail(f"{tool['id']} source is not HTTPS")
        if SHA.fullmatch(tool["revision"]) is None:
            fail(f"{tool['id']} revision is not an exact commit")
        if not re.fullmatch(r"0\.[0-9]+\.[0-9]+", tool["owner"]):
            fail(f"{tool['id']} has invalid owning milestone")
        if len(tool["use"].strip()) < 20:
            fail(f"{tool['id']} requires a substantive use")
        if tool["source_kind"] == "git-tag":
            if VERSION.fullmatch(tool["version"]) is None or not tool["tag"]:
                fail(f"{tool['id']} release pin is malformed")
        elif NIGHTLY.fullmatch(tool["version"]) is None:
            fail(f"{tool['id']} nightly pin is malformed")
        if tool["id"] == "kani":
            if tool["execution_toolchain"] != "1.90.0-x86_64-unknown-linux-gnu":
                fail("Kani execution toolchain drifted")
        elif tool["source_kind"] == "git-tag":
            if tool["execution_toolchain"] != "external-native":
                fail(f"{tool['id']} execution boundary drifted")
        elif tool["execution_toolchain"] != tool["version"]:
            fail(f"{tool['id']} nightly execution boundary drifted")
        versions.add((tool["id"], tool["version"], tool["revision"]))
    if tuple(sorted(ids)) != TOOL_IDS or len(versions) != len(tools):
        fail("assurance tool inventory is incomplete or duplicated")


def cargo_manifests() -> list[Path]:
    return [ROOT / "Cargo.toml", *sorted(ROOT.glob("crates/*/Cargo.toml"))]


def validate_workflow(workflow: str) -> None:
    for target in TARGETS:
        if workflow.count(f"          - {target}\n") != 1:
            fail(f"CI must contain bare-metal target exactly once: {target}")
    command = "run: cargo check --workspace --all-features --target ${{ matrix.target }}"
    if workflow.count(command) != 1:
        fail("CI bare-metal target command drifted")
    platform_command = "run: python scripts/test-assurance.py"
    if workflow.count(platform_command) != 1:
        fail("native host assurance test command drifted")


def validate_manifest_text(contents: str, tools: list[dict], label: str) -> None:
    lowered = contents.lower()
    for tool in tools:
        if any(token in lowered for token in TOOL_MANIFEST_TOKENS[tool["id"]]):
            fail(f"assurance tool entered Cargo manifest: {tool['id']} in {label}")


def validate_repository(policy: dict) -> None:
    with (ROOT / "rust-toolchain.toml").open("rb") as handle:
        release = tomllib.load(handle)["toolchain"]["channel"]
    with (ROOT / "Cargo.toml").open("rb") as handle:
        msrv = tomllib.load(handle)["workspace"]["package"]["rust-version"]
    if msrv.count(".") == 1:
        msrv += ".0"
    if release != policy["toolchains"]["release"] or msrv != policy["toolchains"]["msrv"]:
        fail("assurance toolchains disagree with Cargo or rust-toolchain.toml")
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    validate_workflow(workflow)
    rust_targets = set(
        subprocess.check_output(
            ["rustc", "--print", "target-list"],
            cwd=ROOT,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
        ).splitlines()
    )
    for target in TARGETS:
        if target not in rust_targets:
            fail(f"pinned Rust does not provide bare-metal target: {target}")
    manifests = cargo_manifests()
    for manifest in manifests:
        validate_manifest_text(
            manifest.read_text(encoding="utf-8"),
            policy["tools"],
            str(manifest.relative_to(ROOT)),
        )
    for relative in (
        policy["mutation"]["runner"],
        policy["differential"]["runner"],
        "scripts/assurance_io.py",
        "scripts/assurance_process.py",
        "scripts/assurance_process_tree.py",
        "scripts/check-bare-metal.sh",
        "scripts/check-assurance.py",
        "scripts/test-assurance.py",
        "scripts/check-kani.sh",
    ):
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            fail(f"missing regular assurance runner: {relative}")


def build_evidence(policy: dict | None = None) -> dict:
    current = read_policy() if policy is None else policy
    validate_policy(current)
    validate_repository(current)
    inputs = [
        POLICY,
        ROOT / ".github" / "workflows" / "ci.yml",
        ROOT / "rust-toolchain.toml",
        ROOT / "docs" / "KANI.md",
        ROOT / "scripts" / "assurance_mutation.py",
        ROOT / "scripts" / "assurance_differential.py",
        ROOT / "scripts" / "assurance_io.py",
        ROOT / "scripts" / "assurance_process.py",
        ROOT / "scripts" / "assurance_process_tree.py",
        ROOT / "scripts" / "assurance_process_tests.py",
        ROOT / "scripts" / "assurance_policy.py",
        ROOT / "scripts" / "assurance-fixture-adapter.py",
        ROOT / "scripts" / "test-assurance.py",
        ROOT / "scripts" / "check-assurance.py",
        ROOT / "scripts" / "check-bare-metal.sh",
        ROOT / "scripts" / "check-kani.sh",
        *cargo_manifests(),
    ]
    return {
        "bare_metal_targets": list(TARGETS),
        "harness_protocol": current["harness"]["protocol"],
        "inputs": {
            str(path.relative_to(ROOT)): file_hash(path) for path in inputs
        },
        "milestone": current["schema"]["milestone"],
        "policy_sha256": file_hash(POLICY),
        "schema": 1,
        "tools": [
            {
                key: tool[key]
                for key in ("id", "owner", "revision", "source_kind", "version")
            }
            for tool in sorted(current["tools"], key=lambda item: item["id"])
        ],
    }


def json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode()


def network_check(policy: dict) -> None:
    for tool in policy["tools"]:
        if tool["source_kind"] != "git-tag":
            continue
        output = subprocess.check_output(
            ["git", "ls-remote", "--tags", "--refs", tool["source"]],
            cwd=ROOT,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
        )
        refs = {
            ref.removeprefix("refs/tags/"): revision
            for revision, ref in (line.split() for line in output.splitlines())
        }
        if refs.get(tool["tag"]) != tool["revision"]:
            fail(f"{tool['id']} upstream tag or revision drifted")
        versions = []
        for tag in refs:
            candidate = tag
            if tool["id"] == "kani":
                if not tag.startswith("kani-"):
                    continue
                candidate = tag.removeprefix("kani-")
            elif tool["id"] == "aflplusplus":
                candidate = tag.removeprefix("v")
            if VERSION.fullmatch(candidate):
                versions.append(candidate)
        if not versions:
            fail(f"{tool['id']} upstream has no comparable release tags")
        latest = max(versions, key=version_key)
        if latest != tool["version"]:
            fail(
                f"{tool['id']} pin is stale: "
                f"{tool['version']} is not latest {latest}"
            )


def version_key(version: str) -> tuple[int, int, int, int]:
    match = re.fullmatch(
        r"([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?([a-z])?", version
    )
    if match is None:
        fail(f"cannot compare assurance tool version: {version}")
    major, minor, patch, suffix = match.groups()
    return (
        int(major),
        int(minor or 0),
        int(patch or 0),
        ord(suffix) if suffix else 0,
    )
