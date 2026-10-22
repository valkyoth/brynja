"""Bounded push diagnostics. No release receipts, approvals or deep campaigns."""
from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
import tomllib
from pathlib import Path

import push_ci_baseline as baseline
import verification_commands as commands
import verification_plan as plans


EXTRA = ('python3 scripts/release/test-push-ci.py',
         'python3 scripts/release/check-acceptance-metadata.py',
         'python3 scripts/release/test-acceptance-metadata.py',
         'python3 scripts/assurance/check-assurance.py')
TIMEOUT = 300  # An exceeded diagnostic is a failure, never deferred success.


def catalog(root: Path = plans.ROOT) -> dict[str, list[str]]:
    doc = tomllib.loads((root / 'scripts/ci/push-catalog.toml').read_text())
    if (set(doc) != {'schema', 'baseline', 'affected', 'qualification'}
            or type(doc['schema']) is not int or doc['schema'] != 1):
        raise ValueError('invalid push catalog schema')
    full = commands.repository_commands()
    entries = []
    for kind in ('baseline', 'affected', 'qualification'):
        group = doc[kind]
        if not isinstance(group, list) or not all(isinstance(c, str) for c in group):
            raise ValueError('invalid push catalog commands')
        entries.extend(group)
    if len(entries) != len(set(entries)) or set(entries) != set(full):
        raise ValueError('classify every release command exactly once in the push catalog')
    commands.selected(full, list(plans.scope.GROUPS), full=True)
    return {key: doc[key] for key in ('baseline', 'affected', 'qualification')}


def build(root: Path = plans.ROOT) -> dict:
    inventory = catalog(root)
    base, reason = baseline.find(root)
    groups = list(plans.scope.GROUPS)
    if base is not None:
        try:
            # No rename elision: deletions and both sides of moves affect scope.
            paths = baseline.git(root, 'diff', '--name-only', '--no-renames', '-z', base, 'HEAD')
            paths = paths.decode('utf-8').rstrip('\0').split('\0') if paths else []
            # Manifest/lock changes are conservative here, unlike reviewed
            # release reuse. Unknown source changes also select every group.
            if not any(p.endswith(('Cargo.toml', 'Cargo.lock'))
                       or p.startswith(('scripts/release/', 'scripts/ci/')) for p in paths):
                _, selected = plans.scope.select(paths)
                groups = list(selected)
        except (OSError, UnicodeError, subprocess.SubprocessError):
            base, reason = None, 'diff unavailable: all bounded checks'
    selected = set(inventory['baseline']) | set(commands.selected(inventory['affected'], groups))
    chosen = [c for c in commands.repository_commands() if c in selected and c not in EXTRA]
    return dict(kind='push diagnostics, NOT release qualification', base=base, reason=reason,
                groups=groups, commands=list(EXTRA) + chosen,
                unchanged=[c for c in inventory['affected'] if c not in selected],
                qualification=inventory['qualification'])


def execute(command: str) -> None:
    argv = shlex.split(command)
    environment = {k: v for k, v in os.environ.items()
                   if k not in {'GH_TOKEN', 'GITHUB_TOKEN', 'BRYNJA_FULL_VERIFICATION_APPROVAL',
                                'BRYNJA_DETACHED_JOB', 'BRYNJA_DETACHED_RECEIPT', 'BRYNJA_DETACHED_RECEIPTS'}}
    started = time.monotonic()
    print('RUN: ' + command, flush=True)
    # Linux pre-push/CI owns the child process group: timeout must also stop
    # descendants (Cargo/compiler/mutation children), not leave orphan work.
    with subprocess.Popen(argv, cwd=plans.ROOT, env=environment, start_new_session=True) as process:
        try:
            status = process.wait(timeout=TIMEOUT)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    elapsed = time.monotonic() - started
    print(f'END: {elapsed:.1f}s; exit={status}; {command}', flush=True)
    if status:
        raise subprocess.CalledProcessError(status, argv)


def run(check: bool = False) -> int:
    plan = build()
    print(f'Push CI: {plan["reason"]}; base={plan["base"]}; groups={plan["groups"]}', flush=True)
    print(f'{len(plan["commands"])} bounded checks; {len(plan["unchanged"])} unchanged affected checks; '
          f'{len(plan["qualification"])} checks retained for release qualification.', flush=True)
    for command in plan['unchanged']:
        print('UNCHANGED SINCE SUCCESSFUL CI: ' + command, flush=True)
    print('No release approval consumed or granted; no qualification receipt produced.', flush=True)
    if not check:
        for command in plan['commands']:
            execute(command)
        print('Push diagnostics: PASS (not release qualification).', flush=True)
    return 0
