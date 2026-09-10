#!/usr/bin/env python3
"""Run the explained affected suites; uncertain full runs require approval."""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

import verification_commands as commands
import verification_plan as plans


def execute(command: str, stdin: str | None = None) -> None:
    argv = shlex.split(command)
    environment = dict(os.environ)
    if argv[0].startswith("RUSTFLAGS="):
        environment["RUSTFLAGS"] = argv.pop(0).split("=", 1)[1]
    print("RUN: " + command, flush=True)
    if stdin is None:
        subprocess.run(argv, cwd=plans.ROOT, env=environment, check=True)
    else:
        with (plans.ROOT / stdin).open("rb") as source:
            subprocess.run(argv, cwd=plans.ROOT, env=environment, stdin=source, check=True)


def prepare_matrix(catalog: list[tuple[str, str | None]]) -> None:
    versions = sorted({shlex.split(command)[1].removeprefix("+") for command, _ in catalog})
    installed = subprocess.check_output(["rustup", "toolchain", "list"], text=True).splitlines()
    for version in versions:
        if not any(line.split()[0].split("-", 1)[0] == version for line in installed if line.strip()):
            execute(f"rustup toolchain install {version} --profile minimal")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("plan", "repository", "asan", "miri", "kani", "matrix", "command"))
    parser.add_argument("--base")
    parser.add_argument("--approve-full", default=os.environ.get("BRYNJA_FULL_VERIFICATION_APPROVAL") or None)
    parser.add_argument("--check", action="store_true", help="plan only; never run tests")
    args, extra = parser.parse_known_args()
    if extra and args.phase != "command":
        parser.error("unexpected verification arguments")
    try:
        plan = plans.build(base=args.base)
        print(plans.explain(plan), flush=True)
        # Validate ALL command ownership before starting even the first test.
        catalog = commands.repository_commands()
        commands.selected(catalog, list(plans.scope.GROUPS), full=True)
        sanitizer_catalog = commands.catalog(plans.ROOT / "scripts/zeroization/check-zeroization-sanitizer.sh")
        commands.selected(sanitizer_catalog, list(plans.scope.GROUPS), full=True)
        matrix_catalog = commands.matrix_commands()
        plans.authorize(plan, args.approve_full)
        if args.phase == "plan" or args.check:
            return 0
        full = plan["stage"] == "public" or plan["approval_required"]
        groups = list(plans.scope.GROUPS) if full else plan["groups"]
        if args.phase == "repository":
            chosen = commands.selected(catalog, groups, full=full)
            for command in catalog:
                if command not in chosen:
                    print("REUSE (unchanged input closure): " + command, flush=True)
            for command in chosen:
                execute(command)
        elif args.phase == "command":
            if extra and extra[0] == "--":
                extra = extra[1:]
            command = shlex.join(extra)
            if not extra:
                raise ValueError("missing verification command")
            if commands.selected([command], groups, full=full):
                execute(command)
            else:
                print("REUSE (unchanged input closure): " + command)
        elif args.phase == "matrix":
            if not groups and not full:
                print("REUSE: compiler matrix; no affected implementation or compiler change")
                return 0
            chosen = [(c, stdin) for c, stdin in matrix_catalog if commands.selected([c], groups, full=full)]
            prepare_matrix(chosen)
            for command, stdin in chosen:
                execute(command, stdin)
        elif args.phase == "asan":
            chosen = commands.selected(sanitizer_catalog, plan["verifiers"]["asan"], full=full)
            for command in chosen:
                execute(command)
        elif args.phase == "miri":
            groups = list(plans.scope.GROUPS) if full else plan["verifiers"]["miri"]
            if groups:
                execute("scripts/zeroization/check-zeroization-miri.sh --selected " + " ".join(groups))
            else:
                print("REUSE: all unchanged Miri groups; native repository smoke checks remain")
        else:
            groups = list(plans.scope.GROUPS) if full else plan["verifiers"]["kani"]
            if groups:
                execute("scripts/assurance/check-kani.sh --required-groups " + " ".join(groups))
            else:
                execute("scripts/assurance/check-kani.sh --policy-only")
                print("REUSE: unchanged Kani harnesses and dependencies")
        return 0
    except PermissionError as error:
        print(str(error), file=sys.stderr)
        return 3
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"verification planning/execution failed; release remains incomplete: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
