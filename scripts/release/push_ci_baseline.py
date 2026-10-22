"""Read-only successful Actions ancestry, never release-evidence approval."""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path


CONTRACTS = (
    '.github/workflows/ci.yml', 'scripts/checks.sh', 'scripts/ci/push-catalog.toml',
    'scripts/release/run-verification.py', 'scripts/release/push_ci.py',
    'scripts/release/push_ci_baseline.py', 'scripts/release/test-push-ci.py',
    'scripts/release/verification_commands.py', 'scripts/release/verification_plan.py',
    # Scope selection is conservative, but a changed selector must not inherit
    # success under its old semantics. Include all of its imported scope rules.
    'scripts/zeroization/miri_scope.py', 'scripts/zeroization/scope_inputs.py',
    'scripts/zeroization/scope_review_metadata.py', 'scripts/zeroization/scope_workspace.py',
    'scripts/zeroization/scope_hmac.py',
)


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.PIPE, timeout=15)


def compatible(root: Path, sha: str, head: str) -> bool:
    if not re.fullmatch(r'[0-9a-f]{40}', sha) or sha == head:
        return False
    try:
        git(root, 'merge-base', '--is-ancestor', sha, head)
        return all(git(root, 'show', f'{sha}:{name}') == (root / name).read_bytes()
                   for name in CONTRACTS)
    except (OSError, subprocess.SubprocessError):
        return False


def successful(run: dict, repository: str) -> bool:
    return (run.get('status') == 'completed' and run.get('conclusion') == 'success'
            and run.get('event') == 'push' and run.get('head_branch') == 'main'
            and run.get('path') == '.github/workflows/ci.yml'
            and isinstance(run.get('head_repository'), dict)
            and run['head_repository'].get('full_name') == repository
            and isinstance(run.get('head_sha'), str))


def page(repository: str, number: int) -> list[dict]:
    # Fixed endpoint/branch; caller-supplied --base is not an approval mechanism.
    endpoint = (f'repos/{repository}/actions/workflows/ci.yml/runs'
                f'?branch=main&event=push&status=success&per_page=100&page={number}')
    output = subprocess.check_output(['gh', 'api', endpoint], stderr=subprocess.PIPE, timeout=20)
    runs = json.loads(output)['workflow_runs']
    if not isinstance(runs, list) or len(runs) > 100 or not all(isinstance(run, dict) for run in runs):
        raise ValueError('invalid Actions run inventory')
    return runs


def find(root: Path) -> tuple[str | None, str]:
    repository = os.environ.get('GITHUB_REPOSITORY', '')
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)):
        return None, 'local pre-push: all bounded checks'
    try:
        head = git(root, 'rev-parse', 'HEAD').decode().strip()
        if git(root, 'status', '--porcelain', '--untracked-files=normal').strip():
            return None, 'dirty checkout: all bounded checks'
        for number in range(1, 4):
            runs = page(repository, number)
            for run in runs:
                if successful(run, repository) and compatible(root, run['head_sha'], head):
                    return run['head_sha'], f'successful compatible ancestor Actions run {run["id"]}'
            if len(runs) < 100:
                break
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return None, 'Actions baseline unavailable: all bounded checks'
    return None, 'no successful compatible ancestor: all bounded checks'
