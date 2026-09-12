"""Detached verification lifecycle; no release authority or automatic reuse."""
from __future__ import annotations

import os
import math
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import detached_catalog as catalog
import detached_manifest as records
import detached_shards as shards
import verification_plan as plans

TERMINAL = {"passed", "failed", "cancelled", "timed_out", "log_limit", "interrupted"}


def stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def usage() -> dict:
    # Job-wide observations, not per-thread deltas: concurrent waiters share
    # RUSAGE_CHILDREN. ru_maxrss is a high-water observation, NOT summed RAM.
    import resource
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    owner = resource.getrusage(resource.RUSAGE_SELF)
    scale = 1 if sys.platform == "darwin" else 1024
    return {"children_user_seconds": children.ru_utime,
            "children_system_seconds": children.ru_stime,
            "children_max_rss_bytes": int(children.ru_maxrss * scale),
            "runner_max_rss_bytes": int(owner.ru_maxrss * scale)}


def validate_usage(value: dict) -> None:
    if (not isinstance(value, dict) or set(value) != {
            "children_user_seconds", "children_system_seconds",
            "children_max_rss_bytes", "runner_max_rss_bytes"}):
        raise ValueError("missing detached resource observations")
    for key, number in value.items():
        if (type(number) not in (int, float) or not math.isfinite(number) or number < 0
                or (key.endswith("_bytes") and type(number) is not int)):
            raise ValueError("invalid detached resource observation")


def bounds(seconds: int, log_bytes: int) -> None:
    if type(seconds) is not int or not 1 <= seconds <= 86400:
        raise ValueError("job deadline must be 1..86400 seconds")
    if type(log_bytes) is not int or not 1024 <= log_bytes <= 1024 * 1024 * 1024:
        raise ValueError("job log budget must be 1 KiB..1 GiB")


def clone_inputs(root: Path, destination: Path, closure: dict) -> None:
    # Independent Git objects: no shared mutable worktree, alternate object
    # database, hardlinks, hooks, credentials, or user checkout configuration.
    subprocess.run(["git", "clone", "--no-local", "--no-checkout", "--", str(root), str(destination)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120)
    subprocess.run(["git", "checkout", "--detach", closure["head"]], cwd=destination,
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
    for name, entry in closure["files"].items():
        target = records.safe_path(destination / name)
        if entry is None:
            if target.exists():
                target.unlink()  # Exact tracked deletion, inside new snapshot only.
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(records.safe_path(root / name), target)
            target.chmod(0o700 if entry["executable"] else 0o600)
    if records.sources(destination) != closure or records.sources(root) != closure:
        raise ValueError("source changed while freezing detached checkout")


def start(root: Path, job: Path, phases: list[str], approval: str | None,
          base: str | None, seconds: int, log_bytes: int,
          shard_count: int = 1, workers: int = 1) -> str:
    if sys.platform not in {"linux", "darwin"}:
        raise ValueError("detached execution currently requires Linux or macOS")
    root, job = records.safe_path(root), records.safe_path(job)
    if job.is_relative_to(root) or root.is_relative_to(job):
        raise ValueError("job directory must be outside the source checkout")
    bounds(seconds, log_bytes)
    shards.bounds(shard_count, workers)
    if shard_count > 1 and os.environ.get("CARGO_TARGET_DIR"):
        raise ValueError("clear CARGO_TARGET_DIR so detached shards cannot share build output")
    plan = plans.build(root=root, base=base)
    chosen = catalog.selected(plan, phases, approval, shard_count)
    if plan["issues"] and any("environment" in issue or "RUSTUP_TOOLCHAIN" in issue for issue in plan["issues"]):
        raise ValueError("clear build/verifier environment overrides before detached execution")
    closure = records.sources(root)
    tools = records.tool_identity(root, chosen)
    # Atomic allocation; an existing result/active run is never overwritten.
    job.mkdir(mode=0o700)
    worker = None
    try:
        clone_inputs(root, job / "source", closure)
        if shard_count > 1:
            for index in range(shard_count):
                clone_inputs(root, shards.source(job, index, shard_count), closure)
        frozen = plans.build(root=job / "source", base=plan["base"])
        if frozen != plan:
            raise ValueError("frozen verification plan differs from approved plan")
        manifest = {"schema": 1, "id": uuid.uuid4().hex, "created": stamp(),
                    "plan": plan, "approval": approval, "phases": phases,
                    "commands": chosen, "sources": closure, "tools": tools,
                    "seconds": seconds, "log_bytes": log_bytes,
                    "shards": shard_count, "workers": workers}
        records.atomic(job / "manifest.json", manifest)
        receipt = records.digest(manifest)
        records.atomic(job / "state.json", {"state": "pending", "manifest": receipt})
        # No pipes/PTY or parent-owned session: worker survives SSH/terminal exit.
        with (job / "worker.log").open("xb") as log:
            worker = subprocess.Popen(
                [sys.executable, str(job / "source/scripts/release/detached-verification.py"),
                 "_worker", str(job), "--receipt", receipt],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True, close_fds=True, cwd=job / "source")
        records.atomic(job / "launch.json", {"pid": worker.pid, "manifest": receipt})
        return receipt
    except BaseException:
        if worker is not None:
            with (job / "cancel").open("xb"):
                pass
        # Preserve diagnostic snapshot; a preparation failure is never resumable
        # as success and must use a new directory after correction.
        if not (job / "state.json.tmp").exists():
            records.atomic(job / "state.json", {"state": "failed", "stage": "prepare"})
        raise


def load(job: Path, receipt: str) -> dict:
    records.safe_path(job)
    manifest = records.read(job / "manifest.json")
    if (set(manifest) != {"schema", "id", "created", "plan", "approval", "phases", "commands",
                         "sources", "tools", "seconds", "log_bytes", "shards", "workers"}
            or records.digest(manifest) != receipt or type(manifest.get("schema")) is not int
            or manifest["schema"] != 1):
        raise ValueError("detached launch receipt mismatch")
    bounds(manifest["seconds"], manifest["log_bytes"])
    shards.bounds(manifest["shards"], manifest["workers"])
    if len(manifest["commands"]) > 4096:
        raise ValueError("detached command bound exceeded")
    return manifest


def validate_source(manifest: dict, root: Path) -> None:
    if records.sources(root) != manifest["sources"]:
        raise ValueError("detached source closure changed")
    plan = plans.build(root=root, base=manifest["plan"]["base"])
    if plan != manifest["plan"]:
        raise ValueError("detached plan or approval changed")
    if catalog.selected(plan, manifest["phases"], manifest["approval"], manifest["shards"]) != manifest["commands"]:
        raise ValueError("detached command coverage changed")


def worker(job: Path, receipt: str) -> int:
    manifest = load(job, receipt)
    root = job / "source"
    os.chdir(root)
    # The worker is launched exactly once. Never resume a partially executed
    # command or silently turn an interrupted run into completed evidence.
    with (job / "worker.lock").open("xb"):
        pass
    started, wall = time.monotonic(), stamp()
    results, state = [], "failed"
    failure = None
    try:
        validate_source(manifest, root)
        if records.tool_identity(root, manifest["commands"]) != manifest["tools"]:
            raise ValueError("detached tool identity changed")
        records.atomic(job / "state.json", {"state": "running", "manifest": receipt,
                                            "started": wall, "shards": manifest["shards"],
                                            "workers": manifest["workers"]})
        results, state = shards.run(manifest, job, receipt, started, stamp, validate_source)
        if state == "passed":
            validate_source(manifest, root)
            if records.tool_identity(root, manifest["commands"]) != manifest["tools"]:
                raise ValueError("detached tool identity changed during execution")
            state = "cancelled" if (job / "cancel").exists() else "passed"
    except Exception as error:
        # Store a closed category, not exception payloads which may carry secrets.
        failure = type(error).__name__
        state = "failed"
    terminal = {"schema": 1, "manifest": receipt, "state": state, "started": wall,
                "ended": stamp(), "elapsed_seconds": time.monotonic() - started,
                "results": results, "failure_class": failure, "resources": usage()}
    records.atomic(job / "result.json", terminal)
    records.atomic(job / "state.json", {"state": state, "manifest": receipt,
                                        "result_sha256": records.digest(terminal)})
    return 0 if state == "passed" else 1


def collect(job: Path, receipt: str, root: Path) -> dict:
    manifest = load(job, receipt)
    if (job / "cancel").exists():
        raise ValueError("detached run was cancelled")
    state = records.read(job / "state.json")
    result = records.read(job / "result.json")
    if (set(result) != {"schema", "manifest", "state", "started", "ended", "elapsed_seconds", "results", "failure_class", "resources"}
            or type(result["schema"]) is not int or result["schema"] != 1
            or type(result["elapsed_seconds"]) not in (int, float) or result["elapsed_seconds"] < 0
            or set(state) != {"state", "manifest", "result_sha256"}
            or state["manifest"] != receipt or state["state"] != "passed"
            or state["result_sha256"] != records.digest(result)
            or result["manifest"] != receipt or result["state"] != "passed"
            or result["failure_class"] is not None):
        raise ValueError("detached run is incomplete, unsuccessful or corrupted")
    validate_usage(result["resources"])
    if len(result["results"]) != len(manifest["commands"]):
        raise ValueError("missing detached command results")
    total = 0
    for index, (command, record) in enumerate(zip(manifest["commands"], result["results"])):
        log = f"command-{index:04d}.log"
        if (set(record) != {"state", "exit_code", "elapsed_seconds", "log_bytes", "index", "command",
                            "started", "ended", "log", "log_sha256"}
                or type(record["index"]) is not int or record["index"] != index
                or type(record["log_bytes"]) is not int or record["log_bytes"] < 0
                or type(record["elapsed_seconds"]) not in (int, float) or record["elapsed_seconds"] < 0
                or record["command"] != command
                or record["state"] != "passed" or type(record["exit_code"]) is not int
                or record["exit_code"] != 0 or record["log"] != log
                or record != records.read(job / f"command-{index:04d}.json")
                or record["log_sha256"] != records.file_hash(job / log, manifest["log_bytes"])
                or record["log_bytes"] != (job / log).stat().st_size):
            raise ValueError("detached command/log integrity failure")
        total += record["log_bytes"]
    if total > manifest["log_bytes"] or result["elapsed_seconds"] > manifest["seconds"] + 10:
        raise ValueError("detached resource budget exceeded")
    if records.tool_identity(root, manifest["commands"]) != manifest["tools"]:
        raise ValueError("detached tool identity changed before collection")
    validate_source(manifest, root)
    validate_source(manifest, job / "source")
    for index in range(manifest["shards"]):
        validate_source(manifest, shards.source(job, index, manifest["shards"]))
    return {"state": "validated", "manifest": receipt, "head": manifest["plan"]["head"],
            "phases": manifest["phases"], "commands": len(result["results"]),
            "elapsed_seconds": result["elapsed_seconds"], "resources": result["resources"],
            "release_authorized": False}
