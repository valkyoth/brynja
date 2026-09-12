"""Import completed exact-snapshot commands, without granting release approval."""
from __future__ import annotations

from pathlib import Path
import shlex

import detached_job as jobs
import detached_manifest as records


def completed(job: Path, receipt: str, root: Path, plan: dict,
              phase: str, command: str | None = None) -> bool:
    """Validate the whole job before deciding whether it covers this request.

    An absent phase is not success: the caller must execute it normally. A
    malformed/stale/failed supplied job is an error, never a fallback to PASS.
    """
    job = records.safe_path(job)
    jobs.collect(job, receipt, root)
    manifest = jobs.load(job, receipt)
    if manifest["plan"] != plan:
        raise ValueError("detached evidence does not match this release plan")
    if phase == "command":
        if not command:
            raise ValueError("missing command for detached comparison")
        # Standalone tag commands have no stdin source. Never reuse an artifact
        # for a command that only looks similar or required different stdin.
        expected = shlex.split(command)
        return any(record["stdin"] is None and shlex.split(record["command"]) == expected
                   for record in manifest["commands"])
    if phase not in {"repository", "matrix", "asan", "miri", "kani"}:
        raise ValueError("unsupported detached reuse phase")
    return phase in manifest["phases"]
