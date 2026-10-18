"""Scope workspace dependency-table edits to their actual local consumers."""
import copy

import scope_inputs as inputs


def inherited(value):
    found = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {'dependencies', 'build-dependencies', 'dev-dependencies'}:
                if not isinstance(child, dict):
                    raise ValueError('invalid workspace consumer dependency table')
                found.update(name for name, spec in child.items()
                             if isinstance(spec, dict) and spec.get('workspace') is True)
            else:
                found.update(inherited(child))
    return found


def consumer_paths(root, base, before, after):
    old, new = (copy.deepcopy(inputs.document(raw)) for raw in (before, after))
    tables = []
    for value in (old, new):
        table = value.get('workspace', {}).pop('dependencies', {})
        if not isinstance(table, dict):
            raise ValueError('invalid workspace dependency table')
        tables.append(table)
    if old != new:
        raise ValueError('shared workspace build configuration changed')
    left, right = tables
    changed = {name for name in left.keys() | right.keys() if left.get(name) != right.get(name)}
    names = inputs.git(root, 'ls-tree', '-r', '--name-only', '-z', base).split(b'\0')
    names += inputs.git(root, 'ls-files', '--cached', '--others', '--exclude-standard', '-z').split(b'\0')
    selected = []
    for encoded in sorted(set(names) - {b''}):
        name = encoded.decode()
        if not name.endswith('/Cargo.toml'):
            continue
        for raw in inputs.snapshot(root, base, name):
            if raw is not None and changed.intersection(inherited(inputs.document(raw))):
                selected.append(name)
                break
    # No consumer means an unused workspace declaration, not changed runtime.
    # Actual crate manifests, lock graphs and sources are classified separately.
    return selected
