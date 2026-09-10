"""Explain and bind incremental verification; never approve a full fallback."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FINGERPRINT_INPUT_LIMIT = 64 * 1024 * 1024
BUILD_ENV_PREFIXES = ("RUST", "CARGO_", "CC", "CXX", "MIRI", "KANI", "ASAN_", "LSAN_", "UBSAN_")
sys.path.insert(0, str(ROOT / "scripts/zeroization"))
import miri_scope as scope
import scope_inputs as inputs
import miri_dependencies


def changed_paths(root: Path, base: str) -> list[str]:
    raw = inputs.git(root, "diff", "--name-only", "--no-renames", "-z", base)
    raw += inputs.git(root, "ls-files", "--others", "--exclude-standard", "-z")
    return sorted({p.decode("utf-8") for p in raw.split(b"\0") if p})


def baseline(root: Path) -> str:
    # At a tagged checkout compare against its predecessor, not against itself.
    # CI merge commits still use the nearest first-parent release boundary.
    head = inputs.git(root, "rev-parse", "HEAD").strip()
    tag = inputs.git(root, "describe", "--tags", "--first-parent", "--match", "v[0-9]*", "--abbrev=0", "HEAD").decode().strip()
    if (inputs.git(root, "rev-parse", f"{tag}^{{commit}}").strip() == head
            and not inputs.git(root, "status", "--porcelain", "--untracked-files=all").strip()):
        tag = inputs.git(root, "describe", "--tags", "--first-parent", "--match", "v[0-9]*", "--abbrev=0", "HEAD^").decode().strip()
    return tag


def fingerprint(root: Path, base: str, paths: list[str]) -> str:
    digest = hashlib.sha256()
    digest.update(inputs.git(root, "rev-parse", "HEAD"))
    digest.update(base.encode())
    digest.update(inputs.git(root, "rev-parse", base))
    for path in sorted(set(paths) | {"release-crates.toml"}):
        if scope.normalized(path) != path:
            raise ValueError("noncanonical verification input")
        digest.update(path.encode() + b"\0")
        source = root / path
        if source.is_symlink() or any(p.is_symlink() for p in source.parents if p != root):
            raise ValueError("verification input is symlinked")
        if not source.exists():
            digest.update(b"deleted")
            continue
        if not source.is_file():
            raise ValueError("verification input is not a regular file")
        # The complete roadmap is larger than the semantic TOML/code read cap.
        # Hash metadata incrementally without parsing or unbounded allocation.
        content = hashlib.sha256()
        total = 0
        with source.open("rb") as stream:
            while chunk := stream.read(131072):
                total += len(chunk)
                if total > FINGERPRINT_INPUT_LIMIT:
                    raise ValueError("verification fingerprint input exceeds 64 MiB")
                content.update(chunk)
        digest.update(content.digest())
    for name in sorted(os.environ):
        if name.startswith(BUILD_ENV_PREFIXES):
            digest.update(name.encode() + b"=" + os.environ[name].encode() + b"\0")
    return digest.hexdigest()


def environment_issues(environment: dict[str, str], toolchain: str) -> list[str]:
    # Cache/output paths do not change compilation semantics. Overrides do:
    # unchanged sources are not evidence under unreviewed flags or a wrapper.
    exact = {"RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS",
             "CARGO_ENCODED_RUSTDOCFLAGS", "CARGO_BUILD_TARGET", "RUSTC", "RUSTDOC",
             "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"}
    issues = [f"build/verifier environment override: {name}" for name, value in environment.items()
              if value and (name in exact or name.startswith(("CARGO_PROFILE_", "CARGO_TARGET_", "MIRI", "KANI", "ASAN_", "LSAN_", "UBSAN_")))
              and name != "CARGO_TARGET_DIR"]
    if environment.get("RUSTUP_TOOLCHAIN", toolchain) != toolchain:
        issues.append("RUSTUP_TOOLCHAIN differs from the pinned default compiler")
    return sorted(issues)


def build(root: Path = ROOT, base: str | None = None) -> dict:
    config = inputs.document((root / "release-crates.toml").read_bytes())["release"]
    stage = config["stage"]
    if stage not in ("public", "internal"):
        raise ValueError("unknown release stage")
    toolchain = inputs.document((root / "rust-toolchain.toml").read_bytes())["toolchain"]["channel"]
    issues = environment_issues(dict(os.environ), toolchain)
    base = baseline(root) if base is None else base
    full, groups = scope.select_repository(base, root, issues=issues)
    paths = changed_paths(root, base)
    verifier_groups = {name: list(groups) for name in ("miri", "asan", "kani")}
    miri_full, miri_groups = miri_dependencies.select(root, base, issues)
    verifier_groups['miri'] = list(miri_groups)
    full = full or miri_full
    reasons = []
    if set(miri_groups) != set(groups):
        reasons.append('Miri uses portable owner dependency closures in both lock graphs; native CPU integration checks retain their wider scope')
    for path in paths:
        relevant = set(scope.select([path])[1]).intersection(groups)
        reasons.append(f"{path}: {', '.join(sorted(relevant)) or 'metadata/orchestration: repository checks'}")
    before, after = inputs.snapshot(root, base, "assurance/policy.toml")
    if before is not None and after is not None:
        old = {p["id"]: p for p in inputs.document(before)["tools"]}
        new = {p["id"]: p for p in inputs.document(after)["tools"]}
        for tool, kind in (("miri", "miri"), ("rust-sanitizers", "asan"), ("kani", "kani")):
            if old.get(tool) != new.get(tool):
                verifier_groups[kind] = list(scope.GROUPS)
                issues.append(f"{tool} verifier changed: old evidence is not evidence under the new verifier")
    if stage == "public":
        groups = scope.GROUPS
        verifier_groups = {name: list(scope.GROUPS) for name in verifier_groups}
        reasons.insert(0, "scheduled public crates.io checkpoint: full verification")
    return {
        "schema": 1, "version": config["version"], "stage": stage, "base": base,
        "head": inputs.git(root, "rev-parse", "HEAD").decode().strip(),
        "fingerprint": fingerprint(root, base, paths),
        "approval_required": stage != "public" and bool(full or issues),
        "issues": issues, "groups": list(groups), "verifiers": verifier_groups,
        "reasons": reasons,
        "estimated_runtime": "not measured; a full verifier sweep can take tens of minutes or longer",
    }


def authorize(plan: dict, approval: str | None) -> None:
    if approval is not None and approval != plan["fingerprint"]:
        raise ValueError("full-run approval does not match the current verification plan")
    if plan["approval_required"] and approval != plan["fingerprint"]:
        raise PermissionError(
            "scope review required; no expensive checks started. Correct the classification "
            "or obtain owner approval and pass --approve-full " + plan["fingerprint"]
        )


def explain(plan: dict) -> str:
    return json.dumps(plan, indent=2, sort_keys=True)
