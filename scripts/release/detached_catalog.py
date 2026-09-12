"""Freeze the same selected command set as the foreground verifier."""
from __future__ import annotations

import shlex

import verification_commands as commands
import verification_plan as plans

PHASES = ("repository", "matrix", "asan", "miri", "kani")


def selected(plan: dict, phases: list[str], approval: str | None, shards: int = 1) -> list[dict]:
    if type(shards) is not int or not 1 <= shards <= 8:
        raise ValueError("detached shards must be 1..8")
    plans.authorize(plan, approval)
    if not phases or len(phases) != len(set(phases)) or any(p not in PHASES for p in phases):
        raise ValueError("choose unique registered verification phases")
    repository = commands.repository_commands()
    sanitizer = commands.catalog(plans.ROOT / "scripts/zeroization/check-zeroization-sanitizer.sh")
    matrix = commands.matrix_commands()
    # Validate even commands outside the selected phase, just as foreground does.
    commands.selected(repository, list(plans.scope.GROUPS), full=True)
    commands.selected(sanitizer, list(plans.scope.GROUPS), full=True)
    full = plan["stage"] == "public" or plan["approval_required"]
    groups = list(plans.scope.GROUPS) if full else plan["groups"]
    result = []
    for phase in phases:
        chosen = []
        if phase == "repository":
            chosen = [(c, None) for c in commands.selected(repository, groups, full=full)]
        elif phase == "matrix" and (groups or full):
            chosen = [(c, source) for c, source in matrix if commands.selected([c], groups, full=full)]
        elif phase == "asan":
            chosen = [(c, None) for c in commands.selected(sanitizer, plan["verifiers"][phase], full=full)]
        elif phase in ("miri", "kani"):
            selected_groups = list(plans.scope.GROUPS) if full else plan["verifiers"][phase]
            if selected_groups:
                prefix = ("scripts/zeroization/check-zeroization-miri.sh --selected " if phase == "miri"
                          else "scripts/assurance/check-kani.sh --required-groups ")
                partitions = [selected_groups] if shards == 1 else [[group] for group in selected_groups]
                chosen = [(prefix + " ".join(partition), None) for partition in partitions]
            elif phase == "kani":
                chosen = [("scripts/assurance/check-kani.sh --policy-only", None)]
        for command, source in chosen:
            argv = shlex.split(command)
            environment = {}
            if argv[0].startswith("RUSTFLAGS="):
                environment["RUSTFLAGS"] = argv.pop(0).split("=", 1)[1]
            result.append({"phase": phase, "command": command, "argv": argv,
                           "stdin": source, "environment": environment})
    if len(result) > 4096:
        raise ValueError("too many detached commands")
    return result
