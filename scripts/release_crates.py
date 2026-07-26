#!/usr/bin/env python3
"""Publish changed Brynja crates in dependency order and the facade last."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from release_policy import (
    DEFAULT_PLAN,
    FACADE,
    PUBLISH_ORDER,
    ROOT,
    parse_version,
    publish_plan,
    validate_repository,
)


def run(
    command: list[str],
    *,
    dry_run: bool,
    extra_env: dict[str, str] | None = None,
) -> None:
    print(f"+ {' '.join(command)}", flush=True)
    if dry_run:
        return
    environment = os.environ.copy()
    if extra_env is not None:
        environment.update(extra_env)
    subprocess.run(command, cwd=ROOT, check=True, env=environment)


def capture(command: list[str]) -> str:
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()


def try_capture(command: list[str]) -> str | None:
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def require_clean_tree(*, dry_run: bool) -> None:
    if dry_run:
        return
    status = capture(["git", "status", "--porcelain"])
    if status:
        raise RuntimeError("refusing to publish from a dirty worktree")


def check_release_tag(version: str, *, dry_run: bool) -> bool:
    tag = f"v{version}"
    head = try_capture(["git", "rev-parse", "HEAD"])
    tagged = try_capture(["git", "rev-list", "-n", "1", tag])
    matches = head is not None and tagged is not None and head == tagged
    if matches:
        print(f"Release tag {tag} points at HEAD.")
        return True
    if not dry_run:
        raise RuntimeError(f"refusing to publish unless {tag} points at HEAD")
    print(f"Warning: dry run does not require {tag} at HEAD.", file=sys.stderr)
    return False


def gate_path(version: str) -> Path | None:
    parsed = parse_version(version)
    exact = str(parsed).replace(".", "_").replace("-", "_")
    candidates = [ROOT / "scripts" / f"release_{exact}_gate.sh"]
    if parsed.patch == 0 and parsed.rc is None:
        candidates.append(
            ROOT / "scripts" / f"release_{parsed.major}_{parsed.minor}_gate.sh"
        )
    return next((candidate for candidate in candidates if candidate.exists()), None)


def run_preflight(
    version: str,
    *,
    dry_run: bool,
    release_tag_at_head: bool,
) -> None:
    gate = gate_path(version)
    environment = (
        {"BRYNJA_RELEASE_PUBLISH_TAG": f"v{version}"}
        if release_tag_at_head
        else None
    )
    if gate is None:
        run(["scripts/checks.sh"], dry_run=dry_run)
    else:
        run(
            [str(gate.relative_to(ROOT))],
            dry_run=dry_run,
            extra_env=environment,
        )
    run(["cargo", "deny", "check"], dry_run=dry_run)
    run(["cargo", "audit", "--deny", "warnings"], dry_run=dry_run)


def selected_steps(start_at: str | None, steps: tuple[str, ...]) -> tuple[str, ...]:
    if not steps:
        return ()
    if start_at is None:
        return steps
    if start_at not in steps:
        raise RuntimeError(f"{start_at} is not selected for this release")
    return steps[steps.index(start_at):]


def wait_for_index(package: str, version: str, *, dry_run: bool) -> None:
    print(f"Published {package} {version}.")
    print(f"Confirm https://crates.io/crates/{package}/{version} before continuing.")
    if dry_run:
        print("[dry-run] skipping crates.io wait")
        return
    input("Press Enter after crates.io indexes this version: ")
    time.sleep(5)


def publish(package: str, *, dry_run: bool) -> None:
    run(["cargo", "publish", "-p", package], dry_run=dry_run)


def plan_path(raw: str) -> Path:
    path = Path(raw)
    return path if path.is_absolute() else (ROOT / path).resolve()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Publish changed Brynja support crates in dependency order and "
            "publish brynja for every public release."
        )
    )
    parser.add_argument(
        "--version",
        help="Expected project release version; defaults to release-crates.toml.",
    )
    parser.add_argument(
        "--plan",
        default=str(DEFAULT_PLAN),
        help="Path to the per-crate release plan.",
    )
    parser.add_argument(
        "--start-at",
        choices=PUBLISH_ORDER,
        help="Resume at a selected package after earlier publications succeeded.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate policy, versions, publishability, pins, and order, then exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the guarded publication sequence without publishing.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the typed release-version confirmation.",
    )
    args = parser.parse_args()

    try:
        plan = validate_repository(plan_path(args.plan))
        version = args.version or plan["version"]
        if version != plan["version"]:
            raise RuntimeError(
                f"--version {version} does not match release plan {plan['version']}"
            )
        steps = selected_steps(args.start_at, publish_plan(plan))
        if plan["stage"] == "public" and (not steps or steps[-1] != FACADE):
            raise RuntimeError(f"{FACADE} must be the final published crate")
        if args.check:
            print(
                f"release plan {version} is valid for stage={plan['stage']} "
                f"with {len(steps)} selected crate(s)"
            )
            return 0
        if plan["stage"] != "public":
            raise RuntimeError("foundation plans cannot publish crates")

        require_clean_tree(dry_run=args.dry_run)
        tag_at_head = check_release_tag(version, dry_run=args.dry_run)
        print(f"Workspace root: {ROOT}")
        print(f"Release version: {version}")
        print("Publish sequence:")
        for package in steps:
            entry = plan["crates"][package]
            print(f"  - {package} {entry['version']} ({entry['change']})")
        if not args.yes:
            answer = input("Type the release version to start publishing: ").strip()
            if answer != version:
                raise RuntimeError("version confirmation did not match")

        run_preflight(
            version,
            dry_run=args.dry_run,
            release_tag_at_head=tag_at_head,
        )
        for index, package in enumerate(steps):
            publish(package, dry_run=args.dry_run)
            if index != len(steps) - 1:
                wait_for_index(
                    package,
                    plan["crates"][package]["version"],
                    dry_run=args.dry_run,
                )
        print("Release publish sequence completed.")
        print(f"Recommended follow-up: cargo info {FACADE}@{version}")
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
