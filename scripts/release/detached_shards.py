"""Independent bounded build shards; exact command indices remain receipt-bound."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import time
from pathlib import Path

import detached_manifest as records
import detached_process as process


def bounds(count: int, workers: int) -> None:
    if type(count) is not int or not 1 <= count <= 8:
        raise ValueError("detached shards must be 1..8")
    if type(workers) is not int or not 1 <= workers <= count:
        raise ValueError("detached workers must be 1..shards")


def source(job: Path, index: int, count: int) -> Path:
    return job / ("source" if count == 1 else f"source-{index:02d}")


def partition(commands: list[dict], count: int) -> list[list[tuple[int, dict]]]:
    bounds(count, 1)
    return [list(enumerate(commands))[index::count] for index in range(count)]


def cancel(job: Path) -> None:
    try:
        with (job / "cancel").open("xb"):
            pass
    except FileExistsError:
        pass


def run(manifest: dict, job: Path, receipt: str, started: float, stamp, validate) -> tuple[list, str]:
    """Join all shards; the first failure cancels queued and running siblings.

    Each shard has its own source/build tree and log allowance. Command indices
    and result ordering never depend on scheduling or completion order.
    """
    count, workers = manifest["shards"], manifest["workers"]
    bounds(count, workers)
    groups = partition(manifest["commands"], count)
    allowances = [manifest["log_bytes"] // count + (i < manifest["log_bytes"] % count)
                  for i in range(count)]

    def shard(index: int) -> tuple[list, str]:
        root = source(job, index, count)
        results, consumed = [], 0
        try:
            validate(manifest, root)
            for command_index, command in groups[index]:
                records.atomic(job / f"shard-{index:02d}.json",
                               {"state": "running", "manifest": receipt,
                                "completed": len(results), "current": command_index})
                validate(manifest, root)
                remaining = manifest["seconds"] - (time.monotonic() - started)
                if (job / "cancel").exists():
                    return results, "cancelled"
                if remaining <= 0 or consumed >= allowances[index]:
                    cancel(job)
                    return results, "timed_out" if remaining <= 0 else "log_limit"
                log = job / f"command-{command_index:04d}.log"
                environment = dict(os.environ)
                # A verifier must execute, not recursively import an ancestor's receipt.
                environment.pop("BRYNJA_DETACHED_JOB", None)
                environment.pop("BRYNJA_DETACHED_RECEIPT", None)
                environment.update(command["environment"])
                before = stamp()
                result = process.execute(command["argv"], root, log, job / "cancel",
                                         seconds=remaining, maximum=allowances[index] - consumed,
                                         environment=environment, stdin=command["stdin"])
                result.update({"index": command_index, "command": command, "started": before,
                               "ended": stamp(), "log": log.name,
                               "log_sha256": records.file_hash(log, manifest["log_bytes"])})
                consumed += result["log_bytes"]
                results.append(result)
                records.atomic(job / f"command-{command_index:04d}.json", result)
                if result["state"] != "passed":
                    cancel(job)
                    return results, result["state"]
            validate(manifest, root)
            state = "cancelled" if (job / "cancel").exists() else "passed"
            records.atomic(job / f"shard-{index:02d}.json",
                           {"state": state, "manifest": receipt, "completed": len(results)})
            return results, state
        except Exception:
            cancel(job)
            raise

    results, states, error = [], [], None
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="verification") as pool:
        futures = [pool.submit(shard, index) for index in range(count)]
        for future in as_completed(futures):
            try:
                completed, state = future.result()
                results.extend(completed)
                states.append(state)
            except Exception as failure:
                error = failure
                cancel(job)
    if error is not None:
        raise error
    results.sort(key=lambda item: item["index"])
    # Preserve the concrete failure instead of replacing it with sibling cancellation.
    state = next((s for s in states if s not in {"passed", "cancelled"}),
                 "cancelled" if "cancelled" in states else "passed")
    if state == "passed" and [item["index"] for item in results] != list(range(len(manifest["commands"]))):
        raise ValueError("detached shard coverage is incomplete")
    return results, state
