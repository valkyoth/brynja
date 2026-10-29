"""Resolve Miri coverage in each validated snapshot, never by task ordinal alone.

This proves command meaning only. Source, tool, receipt and approval checks are
still required by the caller. Instances are local to one validation decision;
do not retain them across edits. No Python from archived snapshots is executed.
"""
import json
import shlex

import verification_plan as plans
import miri_tasks


def is_task(entry):
    return entry.get('argv', [])[:2] == ['python3', miri_tasks.RUNNER]


class Resolver:
    def __init__(self, root):
        self.root = root
        self.catalogs = {}
        self.entries = {}

    def key(self, entry):
        if not is_task(entry):
            return None
        encoded = json.dumps(entry, sort_keys=True)
        if encoded in self.entries:
            return self.entries[encoded]
        argv = entry['argv']
        if (set(entry) != {'phase', 'command', 'argv', 'stdin', 'environment'}
                or entry['phase'] != 'miri' or entry['stdin'] is not None
                or entry['environment'] != {} or shlex.split(entry['command']) != argv
                or len(argv) not in (6, 8) or argv[2] != '--group' or argv[4] != '--task'
                or argv[3] not in plans.scope.GROUPS
                or not argv[5].isascii() or not argv[5].isdigit()
                or str(int(argv[5])) != argv[5]
                or (len(argv) == 8 and (argv[6] != '--profile'
                                       or argv[7] not in ('routine', 'extended')))):
            raise ValueError('invalid Miri coverage command')
        group, profile = argv[3], argv[7] if len(argv) == 8 else 'existing-full'
        catalog_key = (group, profile)
        if catalog_key not in self.catalogs:
            self.catalogs[catalog_key] = miri_tasks.task_inventory(self.root, group, profile)
        tasks = self.catalogs[catalog_key]
        number = int(argv[5])
        if number >= len(tasks):
            raise ValueError('Miri coverage task outside snapshot catalog')
        # Compare the complete definition, including features, selectors,
        # completion marker, width and explicit bounded-coverage designation.
        key = json.dumps({'group': group, 'profile': profile, 'task': tasks[number]}, sort_keys=True)
        self.entries[encoded] = key
        return key


class Coverage:
    def __init__(self, old_root, new_root):
        self.old = Resolver(old_root)
        self.new = Resolver(new_root)

    def covers(self, old, new):
        if not is_task(old) or not is_task(new):
            return False
        return self.old.key(old) == self.new.key(new)
