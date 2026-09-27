"""Per-command checkpoints for schema-2 jobs, never inferred from legacy logs.

These are trusted-owner drift checks, not signatures against a hostile runner.
A resume creates a new immutable job; it never restarts an interpreter or
changes the cancelled parent's terminal state. Failed commands are deliberately
not eligible for automatic resume: investigate their failure first.
"""
from __future__ import annotations

import math
import shutil
from pathlib import Path

import detached_manifest as records


def identity(manifest: dict) -> dict:
    return {key: records.digest(manifest[key]) for key in ("sources", "tools")}


def seal(manifest: dict, root: Path, validate) -> dict:
    validate(manifest, root)
    if records.tool_identity(root, manifest["commands"]) != manifest["tools"]:
        raise ValueError("checkpoint tool identity changed")
    return identity(manifest)


def validate_record(manifest: dict, job: Path, record: dict) -> None:
    index = record.get("index")
    if type(index) is not int or not 0 <= index < len(manifest["commands"]):
        raise ValueError("invalid checkpoint command index")
    expected = {"state", "exit_code", "elapsed_seconds", "log_bytes", "index", "command",
                "started", "ended", "log", "log_sha256", "checks"}
    log = f"command-{index:04d}.log"
    if (set(record) != expected or record["command"] != manifest["commands"][index]
            or record["checks"] != identity(manifest)
            or record["state"] != "passed" or type(record["exit_code"]) is not int
            or record["exit_code"] != 0 or record["log"] != log
            or type(record["log_bytes"]) is not int or record["log_bytes"] < 0
            or type(record["elapsed_seconds"]) not in (int, float)
            or not math.isfinite(record["elapsed_seconds"]) or record["elapsed_seconds"] < 0
            or record != records.read(job / f"command-{index:04d}.json")
            or record["log_sha256"] != records.file_hash(job / log, manifest["log_bytes"])
            or record["log_bytes"] != (job / log).stat().st_size):
        raise ValueError("checkpoint command/log integrity failure")


def completed(job: Path, receipt: str, *, depth: int = 0,
              budget: list[int] | None = None) -> tuple[dict, dict[int, dict]]:
    # Import locally: the job module uses this module for schema-2 collection.
    import detached_job as jobs
    budget = [128] if budget is None else budget
    budget[0] -= 1
    if depth > 16 or budget[0] < 0:
        raise ValueError("checkpoint ancestry exceeds bound")
    job = records.safe_path(job)
    manifest = jobs.load(job, receipt)
    if manifest["schema"] != 2:
        raise ValueError("legacy jobs lack per-command post-validation; not resumable")
    state, terminal = records.read(job / "state.json"), records.read(job / "result.json")
    if (set(state) != {"state", "manifest", "result_sha256"}
            or set(terminal) != {"schema", "manifest", "state", "started", "ended",
                                 "elapsed_seconds", "results", "failure_class", "resources"}
            or state["manifest"] != receipt or state["result_sha256"] != records.digest(terminal)
            or terminal.get("manifest") != receipt or terminal.get("schema") != 2
            or terminal.get("state") != state["state"]
            or state["state"] not in {"passed", "partial", "cancelled", "timed_out", "log_limit"}
            or terminal.get("failure_class") is not None):
        raise ValueError("resume requires a terminal successful or resource-interrupted job")
    jobs.validate_usage(terminal["resources"])
    if (type(terminal["elapsed_seconds"]) not in (int, float)
            or not math.isfinite(terminal["elapsed_seconds"]) or terminal["elapsed_seconds"] < 0
            or not isinstance(terminal["results"], list)
            or len(terminal["results"]) > len(manifest["commands"])):
        raise ValueError("invalid checkpoint terminal observations")
    jobs.validate_source(manifest, job / "source")
    seal(manifest, job / "source", jobs.validate_source)
    found, seen = {}, set()
    for record in terminal["results"]:
        index = record.get("index")
        if type(index) is not int or index in seen or not 0 <= index < len(manifest["commands"]):
            raise ValueError("duplicate or invalid checkpoint result")
        seen.add(index)
        # Even interruption records must be bound to the frozen command and file.
        if (record.get("command") != manifest["commands"][index]
                or record != records.read(job / f"command-{index:04d}.json")):
            raise ValueError("checkpoint result changed")
        if record["state"] == "passed":
            validate_record(manifest, job, record)
            found[index] = record
        elif record["state"] not in {"cancelled", "timed_out", "log_limit"}:
            raise ValueError("failed command needs investigation, not automatic resume")
    for index, record in inherited(manifest, depth=depth + 1, budget=budget).items():
        if found.get(index) != record:
            raise ValueError("inherited checkpoint missing or replaced")
    return manifest, found


def inherited(manifest: dict, *, depth: int = 0, budget: list[int] | None = None) -> dict[int, dict]:
    references = manifest.get("resume")
    if references is None:
        return {}
    if isinstance(references, dict):
        references = [references]
    if not isinstance(references, list) or not 1 <= len(references) <= 8:
        raise ValueError("checkpoint parent count must be 1..8")
    found, seen = {}, set()
    budget = [128] if budget is None else budget
    for reference in references:
        if (not isinstance(reference, dict) or set(reference) != {"job", "receipt"}
                or not isinstance(reference["job"], str) or not Path(reference["job"]).is_absolute()
                or not isinstance(reference["receipt"], str)):
            raise ValueError("invalid checkpoint parent")
        key = (reference["job"], reference["receipt"])
        if key in seen:
            raise ValueError("duplicate checkpoint parent")
        seen.add(key)
        parent, passed = completed(Path(reference["job"]), reference["receipt"], depth=depth, budget=budget)
        # Resource budgets and scheduling may change. Everything executed must not.
        for field in ("sources", "tools", "commands", "plan", "phases", "approval", "miri_profile"):
            if parent[field] != manifest[field]:
                raise ValueError("checkpoint execution inputs differ: " + field)
        for index, record in passed.items():
            # Repeated passes are retained in their parent, never counted twice.
            found.setdefault(index, record)
    return found


def install(manifest: dict, job: Path) -> dict[int, dict]:
    found = inherited(manifest)
    if found:
        references = manifest["resume"]
        if isinstance(references, dict):
            references = [references]
        for index, record in found.items():
            parents = [records.safe_path(Path(ref["job"])) for ref in references]
            parent = next(path for path in parents
                          if (path / f"command-{index:04d}.json").exists()
                          and records.read(path / f"command-{index:04d}.json") == record)
            # Independent copies, never writable links into earlier evidence.
            with (job / record["log"]).open("xb") as output:
                with records.safe_path(parent / record["log"]).open("rb") as source:
                    shutil.copyfileobj(source, output)
            records.atomic(job / f"command-{index:04d}.json", record)
            validate_record(manifest, job, record)
    return found


def indices(manifest: dict) -> set[int]:
    part = manifest.get("partition")
    if part is None:
        return set(range(len(manifest["commands"])))
    if (not isinstance(part, list) or len(part) != 2
            or any(type(value) is not int for value in part)
            or not 0 <= part[0] < part[1] <= 8):
        raise ValueError("partition must be zero-based INDEX/COUNT with COUNT 1..8")
    return set(range(part[0], len(manifest["commands"]), part[1]))
