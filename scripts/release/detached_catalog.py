"""Freeze the same selected command set as the foreground verifier."""
from __future__ import annotations

import shlex

import verification_commands as commands
import verification_plan as plans
from detached_manifest import MAX_COMMANDS

PHASES = ("repository", "matrix", "asan", "miri", "kani")


def selected(plan: dict, phases: list[str], approval: str | None, shards: int = 1,
             *, root=plans.ROOT, miri_tasks: bool = False,
             miri_profile: str = "existing-full", historical: bool = False,
             unit_tests: bool = False) -> list[dict]:
    available = plans.scope.GROUPS
    if historical:
        import historical_groups
        available = historical_groups.inventory(root)
    if type(shards) is not int or not 1 <= shards <= 8:
        raise ValueError("detached shards must be 1..8")
    plans.authorize(plan, approval)
    if not phases or len(phases) != len(set(phases)) or any(p not in PHASES for p in phases):
        raise ValueError("choose unique registered verification phases")
    # Historical coverage cannot include checks first added after execution.
    # Its exact frozen catalog is still parsed, classified and compared with
    # the sealed commands. The current repository baseline remains mandatory.
    repository = (commands.catalog(root / 'scripts/checks.sh', '# BEGIN VERIFICATION CATALOG')
                  if historical else commands.repository_commands(root))
    sanitizer = commands.catalog(root / "scripts/zeroization/check-zeroization-sanitizer.sh")
    matrix = commands.matrix_for_plan(plan, root)
    # Validate even commands outside the selected phase, just as foreground does.
    commands.selected(repository, list(plans.scope.GROUPS), full=True)
    commands.selected(sanitizer, list(plans.scope.GROUPS), full=True)
    result = []
    for phase in phases:
        full = plans.requires_full(plan, phase)
        groups = list(available) if full else plan["groups"]
        chosen = []
        if phase == "repository":
            chosen = [(c, None) for c in commands.selected(repository, groups, full=full)]
        elif phase == "matrix" and (groups or full):
            chosen = [(c, source) for c, source in matrix if commands.selected([c], groups, full=full)]
        elif phase == "asan":
            chosen = [(c, None) for c in commands.selected(sanitizer, plan["verifiers"][phase], full=full)]
        elif phase in ("miri", "kani"):
            selected_groups = list(available) if full else plan["verifiers"][phase]
            if phase == "miri" and selected_groups and miri_tasks:
                from miri_tasks import commands as task_commands
                chosen = [(shlex.join(argv), None) for argv in task_commands(root, selected_groups, miri_profile)]
            elif phase == 'kani':
                partitions = [selected_groups] if shards == 1 or not selected_groups else [[group] for group in selected_groups]
                chosen = [(command, None) for partition in partitions for command in commands.kani_commands(partition)]
            elif selected_groups:
                prefix = ("scripts/zeroization/check-zeroization-miri.sh --selected " if phase == "miri"
                          else "scripts/assurance/check-kani.sh --required-groups ")
                partitions = [selected_groups] if shards == 1 else [[group] for group in selected_groups]
                chosen = [(prefix + " ".join(partition), None) for partition in partitions]
        for command, source in chosen:
            argv = shlex.split(command)
            environment = {}
            if argv[0].startswith("RUSTFLAGS="):
                environment["RUSTFLAGS"] = argv.pop(0).split("=", 1)[1]
            result.append({"phase": phase, "command": command, "argv": argv,
                           "stdin": source, "environment": environment})
    if unit_tests:
        import verification_units
        result = [unit for entry in result for unit in verification_units.expand(entry, root)]
    if len(result) > MAX_COMMANDS:
        raise ValueError("too many detached commands")
    return result
