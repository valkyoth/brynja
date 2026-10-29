"""Read the existing verification inventory without running a verifier."""
from __future__ import annotations

import shlex

import detached_catalog
import detached_manifest as records
import verification_commands
import verification_plan as plans
import miri_tasks


def describe(entry, root, cache=None):
    argv = entry['argv']
    meaning = entry
    label = entry['command']
    bundled = True
    if argv[:2] == ['python3', miri_tasks.RUNNER]:
        group = argv[argv.index('--group') + 1]
        profile = argv[argv.index('--profile') + 1] if '--profile' in argv else 'existing-full'
        number = int(argv[argv.index('--task') + 1])
        cache = {} if cache is None else cache
        key = (root, group, profile)
        if key not in cache:
            cache[key] = miri_tasks.task_inventory(root, group, profile)
        task = cache[key][number]
        # Resolve the meaning, not just the ordinal: inserting a task must not
        # assign an old pass to a different test which acquired its index.
        meaning = {'phase': 'miri', 'group': group, 'profile': profile, 'task': task}
        boundary = task['argv'].index('--') if '--' in task['argv'] else len(task['argv'])
        label = shlex.join(task['argv'][:boundary])
        families = [group]
        bundled = '--exact' not in task['argv']
        if bundled:
            label += ' [remaining suite; inspect skips with show]'
        elif task['marker']:
            label = task['marker'].removeprefix('MIRI_CASE_PASS: ') + f' [{profile}]'
            if task.get('coverage'):
                label = '[' + task['coverage'] + '] ' + label
        else:
            label = task['argv'][boundary - 1] + f' [{profile}]'
    elif entry['phase'] == 'kani' and '--required-groups' in argv:
        families = argv[argv.index('--required-groups') + 1:]
    else:
        families = sorted(verification_commands.owners(entry['command'])) or ['repository']
    return {'id': entry['phase'] + '-' + records.digest(meaning)[:16],
            'families': families, 'label': label, 'bundled': bundled,
            'definition': meaning, 'entry': entry}


def inventory(root, phases, profile):
    # This is a browsable inventory, NOT execution approval or a release plan.
    # Select all families to show never-run tasks too; never launch this list.
    groups = list(plans.scope.GROUPS)
    plan = {'stage': 'internal', 'verification_mode': 'affected',
            'approval_required': False, 'fingerprint': '', 'groups': groups,
            'verifiers': {p: groups for p in ('miri', 'kani', 'asan')},
            'full_phases': list(phases)}
    entries = detached_catalog.selected(plan, phases, None, shards=4,
                                        root=root, miri_tasks=True,
                                        miri_profile=profile, unit_tests=True)
    cache = {}
    result = [describe(entry, root, cache) for entry in entries]
    ids = [row['id'] for row in result]
    if len(ids) != len(set(ids)):
        raise ValueError('dashboard task identity collision')
    return result
