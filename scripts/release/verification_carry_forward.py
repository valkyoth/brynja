"""Reuse successful implementation checks, not whole-checkout release readiness.

The original receipt and logs remain immutable. Current baseline checks always
run, and the delta starts at a validated, clean ancestor snapshot, not an
operator-selected commit. Unknown deltas retain the full-run approval boundary.
"""
from pathlib import Path
import shlex

import detached_catalog as catalog
import detached_job as jobs
import detached_manifest as records
import verification_commands as commands
import verification_plan as plans


def prepare(job: Path, receipt: str, root: Path, release_plan: dict) -> dict:
    job = records.safe_path(job)
    # Validate every exit record, log digest, tool identity and frozen source,
    # but do not pretend the historical checkout is the current checkout.
    result = jobs.collect(job, receipt, job / 'source')
    manifest = jobs.load(job, receipt)
    source = manifest['sources']['head']
    if records.git(job / 'source', 'status', '--porcelain', '--untracked-files=all').strip():
        raise ValueError('carry-forward requires a clean committed evidence snapshot')
    records.git(root, 'merge-base', '--is-ancestor', source, 'HEAD')
    delta = plans.build(root=root, base=source, verified_base=True)
    # A new scheduled public version still needs its full checkpoint. Later
    # docs/tooling edits within that already-tested version may carry forward.
    public_checkpoint = (release_plan['stage'] == 'public' and
                         (manifest['plan']['stage'] != 'public' or
                          manifest['plan'].get('version') != release_plan.get('version')))
    delta['evidence'] = {
        'source_commit': source, 'receipt': receipt, 'completed_commands': result['commands'],
        'current_commit': delta['head'], 'new_public_checkpoint': public_checkpoint,
        'rule': 'current baseline always runs; only unchanged covered implementation checks carry forward',
        'changed_paths': plans.changed_paths(root, source),
    }
    return {'plan': delta, 'manifest': manifest, 'release_plan': release_plan,
            'public_checkpoint': public_checkpoint}


def verifier_groups(entry: dict) -> set[str] | None:
    argv = entry['argv']
    if argv[:2] == ['python3', 'scripts/zeroization/run-miri-task.py']:
        if (len(argv) not in (6, 8) or argv[2] != '--group' or argv[4] != '--task'
                or (len(argv) == 8 and (argv[6] != '--profile' or argv[7] not in ('routine', 'extended')))
                or argv[3] not in plans.scope.GROUPS or not argv[5].isdigit()):
            raise ValueError('unknown recorded Miri task')
        return {argv[3]}
    for program, option in (
        ('scripts/zeroization/check-zeroization-miri.sh', '--selected'),
        ('scripts/assurance/check-kani.sh', '--required-groups'),
    ):
        if len(argv) >= 3 and argv[:2] == [program, option]:
            groups = set(argv[2:])
            if not groups or not groups <= set(plans.scope.GROUPS):
                raise ValueError('unknown recorded verifier group')
            return groups
    return None


def covered(entry: dict, previous: list[dict]) -> bool:
    # A single task is not evidence for every other task in its family.
    if entry['argv'][:2] == ['python3', 'scripts/zeroization/run-miri-task.py']:
        return entry in previous
    wanted = verifier_groups(entry)
    if wanted is not None:
        found = set()
        for old in previous:
            if (old['phase'] == entry['phase'] and old['stdin'] == entry['stdin'] and
                    old['environment'] == entry['environment'] and old['argv'][0] == entry['argv'][0]):
                found.update(verifier_groups(old) or ())
        return wanted <= found
    return entry in previous


def disposition(entry: dict, context: dict) -> str:
    """Every requested command is either run now or backed by completed evidence."""
    if context['public_checkpoint']:
        return 'run: new public checkpoint'
    changed = context['plan'].get('evidence', {}).get('changed_paths', [])
    argv = entry['argv']
    driver = argv[1] if argv[0] == 'python3' else argv[0]
    if driver in changed or entry['stdin'] in changed:
        return 'run: changed command driver or input'
    groups = verifier_groups(entry)
    if groups is None:
        groups = commands.owners(entry['command'])
    # Whole-workspace compatibility checks are implementation checks, not
    # documentation lint. Likewise emitted-code inspection needs code/compiler
    # changes, not a new release-note paragraph, to justify recompilation.
    if entry['phase'] == 'matrix' or entry['command'] == 'python3 scripts/cryptography/check-secret-owner-compiler.py':
        groups = groups or set(plans.scope.GROUPS)
    if not groups:
        return 'run: current repository/tooling baseline'
    delta = context['plan']
    affected = (delta['verifiers'][entry['phase']] if entry['phase'] in delta['verifiers']
                else delta['groups'])
    if plans.requires_full(delta, entry['phase']) or groups.intersection(affected):
        return 'run: changed or unresolved implementation inputs'
    if not covered(entry, context['manifest']['commands']):
        return 'run: no matching successful command evidence'
    return 'reuse: unchanged implementation inputs'


def required(context: dict, phase: str, command: str | None = None) -> list[dict]:
    if phase == 'command':
        if not command:
            raise ValueError('missing verification command')
        commands.owners(command)  # Unknown commands never become successful skips.
        argv = shlex.split(command)
        environment = {}
        if argv[0].startswith('RUSTFLAGS='):
            environment['RUSTFLAGS'] = argv.pop(0).split('=', 1)[1]
        return [{'phase': 'repository', 'command': command, 'argv': argv,
                 'stdin': None, 'environment': environment}]
    phases = list(catalog.PHASES) if phase == 'plan' else [phase]
    plan = context['release_plan']
    # Enumerate requirements, not permission to execute: main() separately
    # authorizes the delta before executing anything. Split verifier groups so
    # a changed family cannot force an unrelated family to run again.
    approval = plan['fingerprint'] if plan['approval_required'] else None
    from miri_cases import profile_for
    manifest = context.get('manifest', {})
    requested = manifest.get('miri_profile') if plan['stage'] == 'internal' else None
    return catalog.selected(plan, phases, approval, shards=8, miri_tasks=True,
                            miri_profile=profile_for(plan['stage'], requested))
