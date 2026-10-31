"""Finite pre-push checks and a publication-only handoff, from v0.25.3.

This is deliberately not an evidence-reuse engine. The owner reviews the
explicit check list and records its completion. Publishing reads Git/GitHub
identity and status only; it never reruns the gate or deep verification.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import signal
import os
import subprocess
import sys
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLAN = 'scripts/release/final-checks.toml'


def enabled(version: str) -> bool:
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-rc\.\d+)?', version.removeprefix('v'))
    if match is None:
        raise ValueError('expected vMAJOR.MINOR.PATCH[-rc.N]')
    return tuple(map(int, match.groups())) >= (0, 25, 3)


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(['git', *args], cwd=root, text=True).strip()


def load(version: str, root: Path = ROOT) -> dict:
    plan = tomllib.loads((root / PLAN).read_text())
    if (plan.get('schema') != 1 or plan.get('version') != version.removeprefix('v')
            or not plan.get('scope') or not plan.get('checks')):
        raise ValueError('review the finite final-checks.toml list for this version first')
    seen = set()
    for check in plan['checks']:
        if (set(check) != {'id', 'command', 'timeout_seconds'}
                or not re.fullmatch(r'[a-z0-9-]+', check['id'])
                or check['id'] in seen or not check['command']
                or not all(isinstance(x, str) and x for x in check['command'])
                or type(check['timeout_seconds']) is not int
                or not 1 <= check['timeout_seconds'] <= 1200):
            raise ValueError('invalid finite release check')
        seen.add(check['id'])
    return plan


def pentest(version: str, root: Path = ROOT, *, allow_pending: bool = False) -> None:
    """Inspect the committed disposition, not every prior implementation."""
    version = 'v' + version.removeprefix('v')
    name = f'security/pentest/{version}.md'
    raw = git(root, 'show', f'HEAD:{name}')
    pending = allow_pending and re.findall(r'^Status: (.*)$', raw, re.MULTILINE) == ['RETEST REQUIRED']
    for field, expected in [('Version', version), ('Status', 'RETEST REQUIRED' if pending else 'PASS'),
                            ('Retest', 'PENDING' if pending else 'PASS'), ('Open-Findings', '0')]:
        if re.findall(rf'^{field}: (.*)$', raw, re.MULTILINE) != [expected]:
            raise ValueError(f'{name} must record exactly one {field}: {expected}')
    for field in ('Date', 'Tester', 'Scope'):
        values = re.findall(rf'^{field}: (.+)$', raw, re.MULTILINE)
        if len(values) != 1 or not values[0].strip():
            raise ValueError(f'{name} requires {field}')
        if field == 'Date':
            datetime.date.fromisoformat(values[0])
    # No requirement to touch the report on every documentation/CI commit.
    # Relevant post-review changes still require an honest scoped disposition.


def candidate(version: str, root: Path = ROOT) -> None:
    if git(root, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('final release candidate must be committed and clean')
    current = tomllib.loads((root / 'release-crates.toml').read_text())['release']
    if current['version'] != version.removeprefix('v'):
        raise ValueError('release version differs from the candidate')
    pentest(version, root)


def execute(check: dict, root: Path = ROOT) -> None:
    print(f"RUN {check['id']}: {check['command']}", flush=True)
    started = time.monotonic()
    with subprocess.Popen(check['command'], cwd=root, start_new_session=True) as child:
        try:
            status = child.wait(timeout=check['timeout_seconds'])
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise
    if status:
        raise RuntimeError(f"{check['id']} failed ({status}); completed checks need not be repeated")
    print(f"PASS {check['id']} ({time.monotonic() - started:.1f}s)", flush=True)


def gate(version: str, selected: str | None = None, *, listing: bool = False, ci: bool = False,
         root: Path = ROOT) -> None:
    plan = load(version, root)
    ci_ids = plan.get('ci_checks', [])
    if ci and (not ci_ids or len(ci_ids) != len(set(ci_ids))
               or set(ci_ids) - {c['id'] for c in plan['checks']}):
        raise ValueError('explicit CI check selection is missing or invalid; no full fallback')
    chosen = [c for c in plan['checks'] if (selected is None or c['id'] == selected)
              and (not ci or c['id'] in ci_ids)]
    if not chosen:
        raise ValueError(f'unknown final check: {selected}; no broader selection')
    print(f"Finite release scope: {plan['scope']}")
    if listing:
        for check in chosen:
            print(f"{check['id']}: {check['command']} (limit {check['timeout_seconds']}s)")
        return
    if not ci:
        candidate(version, root)
    before = git(root, 'rev-parse', 'HEAD')
    for check in chosen:
        execute(check, root)
    if git(root, 'rev-parse', 'HEAD') != before or git(root, 'status', '--porcelain'):
        raise RuntimeError('candidate changed during final checks; inspect the affected work')
    if ci:
        print(f'Finite component CI checks PASS for {before}; not release authorization.')
    else:
        print('Selected final check PASS; retain earlier results for other checks.' if selected else
              f'Final release checks PASS for {before}. Push this candidate and wait for green GitHub.')
    print('No native capture, proof, Miri, ASan or compiler campaign selected implicitly.')


def github_green(head: str, runs: list[dict], checks: list[dict]) -> None:
    """Latest push runs and check results for exactly this commit, not a branch badge."""
    latest = {}
    for run in runs:
        if run.get('head_sha') != head or run.get('event') != 'push' or run.get('head_branch') != 'main':
            continue
        key = run['workflow_id']
        if key not in latest or (run['id'], run.get('run_attempt', 1)) > (
                latest[key]['id'], latest[key].get('run_attempt', 1)):
            latest[key] = run
    if not any(r.get('path') == '.github/workflows/ci.yml' for r in latest.values()):
        raise ValueError('no main-push Rust CI result for this exact commit')
    for run in latest.values():
        if run.get('status') != 'completed' or run.get('conclusion') != 'success':
            raise ValueError(f"GitHub workflow not green: {run.get('name', run['workflow_id'])}")
    latest_checks = {}
    for check in checks:
        if check.get('head_sha') != head:
            continue
        key = (check['name'], check['app']['id'])
        if key not in latest_checks or check['id'] > latest_checks[key]['id']:
            latest_checks[key] = check
    if not latest_checks:
        raise ValueError('no check results for the candidate')
    for check in latest_checks.values():
        if check.get('status') != 'completed' or check.get('conclusion') not in ('success', 'neutral', 'skipped'):
            raise ValueError(f"GitHub check not green: {check['name']}")
    # These are the repository's existing CodeQL default-setup checks.
    for name in ('Analyze (python)', 'Analyze (c-cpp)', 'Analyze (rust)', 'Analyze (actions)'):
        if not any(c['name'] == name and c.get('conclusion') == 'success'
                   and c['app'].get('slug') == 'github-actions' for c in latest_checks.values()):
            raise ValueError(f'missing successful CodeQL check: {name}')


def pages(endpoint: str, field: str, root: Path) -> list[dict]:
    raw = subprocess.check_output(['gh', 'api', '--paginate', '--slurp', endpoint], cwd=root)
    return [item for page in json.loads(raw) for item in page[field]]


def publication(version: str, *, dry_run: bool, root: Path = ROOT) -> None:
    if dry_run:
        print('[dry-run] publication handoff: clean tagged candidate + existing green GitHub; no tests')
        return
    candidate(version, root)
    head = git(root, 'rev-parse', 'HEAD')
    tag = 'v' + version.removeprefix('v')
    if git(root, 'rev-parse', f'{tag}^{{commit}}') != head:
        raise ValueError('tag does not identify this candidate')
    subprocess.run(['git', 'verify-tag', tag], cwd=root, check=True)
    repo = 'repos/valkyoth/brynja'
    github_green(head, pages(f'{repo}/actions/runs?head_sha={head}&per_page=100', 'workflow_runs', root),
                 pages(f'{repo}/commits/{head}/check-runs?per_page=100&filter=latest', 'check_runs', root))
    print(f'Publication handoff: existing GitHub results green for {head}. No verification rerun.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version', nargs='?', help='Defaults to the current release plan')
    parser.add_argument('--ci', action='store_true', help='Run only the explicit CI subset; no pentest/release authorization')
    parser.add_argument('--review-only', action='store_true', help='Inspect the committed review disposition only; run no checks')
    parser.add_argument('--allow-pending', action='store_true', help='With --review-only, report pending review without authorizing release')
    parser.add_argument('--list', action='store_true', help='Display the finite list; execute nothing')
    parser.add_argument('--check', help='Run only a named final check after a scoped correction')
    args = parser.parse_args()
    try:
        version = args.version or tomllib.loads((ROOT / 'release-crates.toml').read_text())['release']['version']
        if not enabled(version):
            raise ValueError('scoped release flow starts at v0.25.3')
        if args.review_only:
            if args.ci or args.list or args.check:
                raise ValueError('--review-only cannot execute checks')
            pentest(version, allow_pending=args.allow_pending)
            print('Committed review disposition inspected; no release authorization granted.')
            return 0
        if args.allow_pending:
            raise ValueError('--allow-pending requires --review-only')
        gate(version, args.check, listing=args.list, ci=args.ci)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
