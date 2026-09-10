"""Separate CPU-native consumer regressions from portable-only Miri owners."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'zeroization'))
import scope_inputs as inputs
import miri_scope as scope

PORTABLE_ROOTS = ('brynja-hash-sha3', 'brynja-mac-kmac', 'brynja-hash-tuple',
                  'brynja-hash-parallel', 'brynja-hash-parallel-std')


def graph(before: bytes, after: bytes):
    # Validate BOTH lock graphs with the normal fail-closed schema/edge checker.
    inputs.lock_groups(before, after)
    downstream = {key: set(value) for key, value in scope.DOWNSTREAM.items()}
    for data in (before, after):
        packages = {p['name']: p for p in inputs.document(data)['package']}
        if not set(PORTABLE_ROOTS) <= packages.keys():
            raise ValueError('portable Miri owner missing from lock graph')
        reached, pending = set(), list(PORTABLE_ROOTS)
        while pending:
            name = pending.pop()
            if name in reached:
                continue
            reached.add(name)
            pending.extend(packages[name].get('dependencies', []))
        # Even an optional CPU edge makes reuse conservative. Removing an edge
        # cannot suppress its baseline consumer's checks for this release.
        if reached.intersection({'brynja-crypto-cpu', 'brynja-crypto-cpu-std'}):
            return downstream
    downstream['static_cpu'].discard('sha3')
    return downstream


def select(root, base, issues):
    try:
        before, after = inputs.snapshot(root, base, 'Cargo.lock')
        downstream = graph(before, after)
    except (OSError, KeyError, TypeError, ValueError) as error:
        issues.append('Miri dependency proof unavailable: ' + str(error))
        return True, scope.GROUPS
    return scope.select_repository(base, root, issues=issues, downstream=downstream)
