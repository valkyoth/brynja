"""Bounded, exact-source records for trusted-owner detached verification.

Digests detect drift/corruption, not a malicious operator with write access to
the job directory. No record in this module authorizes a tag or publication.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

MAX_RECORD = 16 * 1024 * 1024
MAX_SOURCE = 64 * 1024 * 1024
MAX_FILES = 20000
MAX_TOTAL = 1024 * 1024 * 1024


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def safe_path(path: Path) -> Path:
    """Reject symlinks before resolution, including parent components."""
    if ".." in path.parts:
        raise ValueError("detached path traversal")
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError(f"symlinked detached input: {item}")
    return path


def file_hash(path: Path, maximum: int = MAX_SOURCE) -> str:
    path = safe_path(path)
    if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > maximum:
        raise ValueError("detached input is non-regular or oversized")
    result = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            total += len(chunk)
            if total > maximum:
                raise ValueError("detached input grew past its bound")
            result.update(chunk)
    return result.hexdigest()


def read(path: Path) -> dict:
    file_hash(path, MAX_RECORD)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate detached record key")
            result[key] = value
        return result
    raw = path.read_bytes()
    if len(raw) > MAX_RECORD:
        raise ValueError("oversized detached record")
    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite detached number")
        return number
    value = json.loads(raw, object_pairs_hook=unique, parse_float=finite,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    if not isinstance(value, dict):
        raise ValueError("detached record must be an object")
    return value


def atomic(path: Path, value: dict) -> None:
    """Publish a complete record; never leave a partially written success file."""
    safe_path(path)
    raw = canonical(value)
    if len(raw) > MAX_RECORD:
        raise ValueError("detached record exceeds limit")
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("xb") as stream:
        os.chmod(temporary, 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=root, timeout=30)


def sources(root: Path) -> dict:
    """All tracked and non-ignored inputs, plus admitted local references.

    The snapshot intentionally excludes build output, credentials and tool
    caches. Ignored local reference files are the single explicit exception.
    """
    safe_path(root)
    paths = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    names = {p.decode("utf-8") for p in paths.split(b"\0") if p}
    refs = root / "references/LOCAL_SHA256SUMS"
    if refs.exists():
        file_hash(refs)
        for line in refs.read_text().splitlines():
            if line.strip():
                _, name = line.split("  ", 1)
                names.add("references/local/" + name)
    if len(names) > MAX_FILES:
        raise ValueError("too many detached source inputs")
    files, total = {}, 0
    for name in sorted(names):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name:
            raise ValueError("non-canonical detached source path")
        path = safe_path(root / relative)
        if not path.exists():
            files[name] = None  # Tracked deletion is part of the snapshot.
            continue
        total += path.stat().st_size
        if total > MAX_TOTAL:
            raise ValueError("detached source closure exceeds 1 GiB")
        files[name] = {"sha256": file_hash(path), "executable": bool(path.stat().st_mode & 0o111)}
    return {"head": git(root, "rev-parse", "HEAD").decode().strip(), "files": files}


def verifier_commands(root: Path, selected: list[dict]) -> dict:
    """Probe actual selected verifier binaries, not just their Rust compiler."""
    names = set()
    for entry in selected:
        argv = entry["argv"]
        if argv[0] == "scripts/zeroization/check-zeroization-miri.sh":
            names.add("miri")
        if argv[0] == "scripts/assurance/check-kani.sh" and "--policy-only" not in argv:
            names.add("kani")
    if not names:
        return {}
    policy = root / "assurance/policy.toml"
    file_hash(policy)
    tools = tomllib.loads(policy.read_text())["tools"]
    result = {}
    for name in sorted(names):
        matches = [tool for tool in tools if tool["id"] == name]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous detached verifier identity")
        result["verifier:" + name] = [
            "rustup", "run", matches[0]["execution_toolchain"], "cargo", name, "--version"]
    return result


def tool_identity(root: Path, selected: list[dict]) -> dict:
    """Record public tool versions, not the environment or credential values."""
    commands = {
        "rustc": ["rustc", "-vV"], "cargo": ["cargo", "-V"],
        "rustup": ["rustup", "--version"],
        "installed": ["rustup", "toolchain", "list"],
        "python3": ["python3", "--version"],
    }
    commands.update(verifier_commands(root, selected))
    versions = {"python": sys.version, "platform": sys.platform}
    for name, command in commands.items():
        value = subprocess.check_output(command, stderr=subprocess.DEVNULL, timeout=30,
                                        env={**os.environ, "RUSTUP_AUTO_INSTALL": "0"})
        if len(value) > 65536:
            raise ValueError("tool identity exceeds bound")
        versions[name] = value.decode().strip()
    # Toolchain names alone do not bind the installed executables (including
    # patched/replaced nightly installations). Hash the installed inventory's
    # compiler identity without dumping cache paths or the environment.
    for line in versions["installed"].splitlines():
        toolchain = line.split()[0]
        value = subprocess.check_output(["rustc", "+" + toolchain, "-vV"],
                                        stderr=subprocess.DEVNULL, timeout=30,
                                        env={**os.environ, "RUSTUP_AUTO_INSTALL": "0"})
        if len(value) > 65536:
            raise ValueError("compiler identity exceeds bound")
        versions["compiler:" + toolchain] = value.decode().strip()
    return versions
