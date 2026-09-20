"""Cheap, manual family-development review; never executes release/test gates."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path


# These are review obligations, not assertions that every algorithm needs an ISA.
DIMENSIONS = {
    "public-api": "All valid operations, streaming/bit/XOF profiles, verification and typed outputs.",
    "portable": "Independent vectors/oracles, bounds, overflow and portable reference behavior.",
    "secret-ownership": "Non-copying owners; borrowed/scoped storage; all owned regions and destinations.",
    "kernel-registers": "Working registers and spills at each claimed normal-return boundary; ABI preservation.",
    "caller-transfers": "Portable and accelerated framing, packing, copies, output conversion and callers, not just kernels.",
    "lifecycle": "Success/error/cancellation/revocation/unwind/Drop; abort and interruption limitations.",
    "side-channels": "Secret-dependent control, addresses, comparisons and exposed length/shape metadata.",
    "x86-instructions": "Dedicated instruction opportunities and exact CPU/OS feature bundles; not just current hosts.",
    "arm-instructions": "Dedicated instruction opportunities and exact CPU/OS feature bundles; not just current hosts.",
    "other-targets": "Other supported targets; explicitly distinguish post-1.0 RISC-V qualification.",
    "single-state-simd": "Useful intra-message SIMD, or a reasoned non-applicability/measurement decision.",
    "batch-simd": "Independent-message/lane SIMD, distinct ordinary and hardened owners, tail behavior.",
    "threading": "Useful bounded parallelism, worker ownership, deterministic joins and result provenance.",
    "dispatch": "Default-off opt-in, portable/prefer/require, health, quarantine, unsupported CPUs and migration trust.",
    "package-api": "Usable extracted-package APIs and feature combinations, no repository-only cfgs.",
    "platform-evidence": "Linux/macOS/Windows ABI and native/emulated/compile-only coverage distinguished.",
    "performance": "Measured representative workloads, scalar fallback/crossover, no assumed SIMD speedup.",
}
STATES = {"needs-review", "reviewed", "inherited", "not-applicable", "planned"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(value) -> str:
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def local_file(root: Path, name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or not path.parts or any(p in (".", "..") for p in path.parts):
        raise ValueError("evidence paths must be repository-relative files")
    target = root / path
    if any((root / Path(*path.parts[:i])).is_symlink() for i in range(1, len(path.parts) + 1)):
        raise ValueError("symlinked review input: " + name)
    if not target.is_file():
        raise ValueError("missing review input: " + name)
    return target


def implementation_snapshot(root: Path) -> dict:
    """Include dirty/untracked Rust and manifests; ignore docs and build artifacts.

    Conservative workspace-wide binding, NOT a test rerun decision. Cargo source
    classification remains the existing planner's responsibility.
    """
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root, check=True, capture_output=True, timeout=30,
    )
    paths = set(result.stdout.decode().split("\0")) - {""}
    rows = {}
    for name in sorted(paths):
        path = Path(name)
        if "target" in path.parts:
            continue
        implementation = name.startswith("crates/") and (path.suffix == ".rs" or path.name == "Cargo.toml")
        configuration = name in {"Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml"} or name.startswith(".cargo/")
        if implementation or configuration:
            if any((root / Path(*path.parts[:i])).is_symlink() for i in range(1, len(path.parts) + 1)):
                raise ValueError("symlinked implementation input: " + name)
            rows[name] = digest(local_file(root, name).read_bytes()) if (root / name).exists() else "deleted"
    if rows.get("Cargo.toml", "deleted") == "deleted" or not any(name.endswith(".rs") and sha != "deleted" for name, sha in rows.items()):
        raise ValueError("empty or incomplete implementation snapshot")
    return {"sha256": fingerprint(rows), "files": len(rows)}


def roadmap(root: Path) -> dict:
    text = (root / "docs/RELEASE_PLAN.md").read_text(encoding="utf-8")
    headings = list(re.finditer(r"^### v([^ ]+) - (.+)$", text, re.MULTILINE))
    result = {}
    for i, match in enumerate(headings):
        version = match[1]
        if version in result:
            raise ValueError("duplicate roadmap version: " + version)
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        result[version] = {"title": match[2], "sha256": digest(text[match.start():end].encode())}
    return result


def template(version: str, closing: str, snapshot: dict, plans: dict) -> dict:
    if version not in plans or closing not in plans:
        raise ValueError("milestone and closing version must exist in the roadmap")
    order = list(plans)
    if version.rsplit(".", 1)[0] != closing.rsplit(".", 1)[0] or order.index(version) > order.index(closing):
        raise ValueError("closing version must be at or after this milestone in the same minor")
    return {
        "schema": 1, "version": version, "closing_version": closing,
        "implementation": snapshot, "reviewer": "", "scope": "",
        "roadmap": {v: plans[v]["sha256"] for v in (version, closing)},
        "decisions": {key: {"status": "needs-review", "reason": "", "evidence": {}, "follow_up": None}
                      for key in DIMENSIONS},
    }


def audit(root: Path, record: dict, expected: dict, plans: dict) -> dict:
    if set(record) != set(expected) or record["schema"] != 1:
        raise ValueError("unknown or missing review fields/schema")
    for key in ("version", "closing_version", "implementation", "roadmap"):
        if record[key] != expected[key]:
            raise ValueError("stale or mismatched review binding: " + key)
    if set(record["decisions"]) != set(DIMENSIONS):
        raise ValueError("every hardening/acceleration dimension needs an explicit disposition")
    if not isinstance(record["reviewer"], str) or not isinstance(record["scope"], str):
        raise ValueError("reviewer and scope must be text")
    issues = []
    if not record["reviewer"].strip() or not record["scope"].strip():
        issues.append("Name the reviewer and the exact identities/profiles/backends covered.")
    rows = []
    order = list(plans)
    start, end = order.index(expected["version"]), order.index(expected["closing_version"])
    for key, question in DIMENSIONS.items():
        row = record["decisions"][key]
        if set(row) != {"status", "reason", "evidence", "follow_up"} or row["status"] not in STATES:
            raise ValueError("invalid decision: " + key)
        if not isinstance(row["reason"], str) or not isinstance(row["evidence"], dict):
            raise ValueError("invalid reason/evidence: " + key)
        for path, sha in row["evidence"].items():
            if digest(local_file(root, path).read_bytes()) != sha:
                raise ValueError("stale evidence: " + path)
        state = row["status"]
        follow = row["follow_up"]
        if state != "planned" and follow is not None:
            raise ValueError("only planned work may name a follow-up")
        if state == "needs-review" or not row["reason"].strip():
            issues.append(key + ": REVIEW NEEDED — " + question)
        elif state == "planned":
            if follow is None:
                issues.append(key + ": ADD/SELECT A NUMBERED MILESTONE before family closure.")
            else:
                if not isinstance(follow, str) or follow not in plans or not start < order.index(follow) <= end:
                    raise ValueError("follow-up must be a later roadmap milestone no later than family closure: " + key)
                if follow.rsplit(".", 1)[0] != expected["version"].rsplit(".", 1)[0]:
                    raise ValueError("follow-up must belong to the same minor family")
                # The actual plan, not only a made-up version string, must be reviewed.
                if row["evidence"].get("docs/RELEASE_PLAN.md") != digest((root / "docs/RELEASE_PLAN.md").read_bytes()):
                    raise ValueError("planned work must bind the reviewed release plan")
                issues.append(key + ": PLANNED, NOT IMPLEMENTED — v" + follow + " " + plans[follow]["title"])
        elif not row["evidence"]:
            issues.append(key + ": EVIDENCE NEEDED (including inherited or not-applicable decisions).")
        rows.append({"dimension": key, **row})
    return {
        "result": "FOLLOW_UP_REQUIRED" if issues else "REVIEW_RECORDED",
        "version": expected["version"], "closing_version": expected["closing_version"],
        "issues": issues, "decisions": rows,
        "available_follow_ups": {v: plans[v]["title"] for v in order[start + 1:end + 1]},
        "limitations": "Reviewed coverage only; not security certification, feasibility discovery, test execution or release approval.",
    }
