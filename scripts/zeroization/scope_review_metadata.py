"""Exact review-only inputs, paired with mandatory current repository checks.

These are not runtime/verifier drivers. No directory-wide exemption is granted.
Production sources, build inputs and memory/proof drivers are independently
classified, and their old receipts still require unchanged execution identities.
"""
import hashlib
import re
from pathlib import PurePosixPath

import scope_inputs as inputs


CPU_CHECKS = (
    'python3 scripts/cpu/check-cpu-boundary.py',
    'python3 scripts/cpu/test-cpu-boundary.py',
    'python3 scripts/cpu/check-cpu-evidence.py',
    'python3 scripts/cpu/test-cpu-evidence.py',
)
KMAC_CHECKS = (
    'python3 scripts/kmac/check-kmac.py',
    'python3 scripts/kmac/test-kmac.py',
    'scripts/kmac/check-kmac-codegen.sh',
)
SCRIPT_COMMANDS = {
    'scripts/cpu/cpu_boundary_policy.py': CPU_CHECKS,
    'scripts/cpu/cpu_boundary_windows.py': CPU_CHECKS,
    'scripts/cpu/test-cpu-boundary.py': CPU_CHECKS,
    'scripts/kmac/check-kmac-codegen.sh': KMAC_CHECKS,
    'scripts/kmac/test-kmac.py': KMAC_CHECKS,
}
BASE_COMMANDS = frozenset((*CPU_CHECKS, *KMAC_CHECKS,
    'python3 scripts/hash/check-final-acceptance.py'))


def cpu_inventory_only(root, base, before, after):
    """Add/rebind inventory only; never change admission, graph or limits.

    Every added or rebound source must exist unchanged in both snapshots and
    its current digest must match. Existing status/path entries cannot vanish.
    """
    left, right = inputs.document(before), inputs.document(after)
    rows = []
    for document in (left, right):
        sources = document.pop('sources')
        inventory = {}
        for row in sources:
            if set(row) != {'package', 'path', 'status', 'sha256'}:
                return False
            package, path = row['package'], row['path']
            if (package not in {'brynja-crypto-cpu', 'brynja-crypto-cpu-std'}
                    or not isinstance(path, str) or not path.startswith('src/')
                    or not path.endswith('.rs') or '..' in PurePosixPath(path).parts
                    or str(PurePosixPath(path)) != path or '\\' in path
                    or not isinstance(row['status'], str)
                    or not isinstance(row['sha256'], str)
                    or not re.fullmatch('[0-9a-f]{64}', row['sha256'])):
                return False
            key = (package, path)
            if key in inventory:
                return False
            inventory[key] = row
        rows.append(inventory)
    old, new = rows
    if left != right or not old.keys() <= new.keys():
        return False
    for key, row in new.items():
        previous = old.get(key)
        if previous is not None and previous['status'] != row['status']:
            return False
        if previous == row:
            continue
        source = 'crates/' + key[0] + '/' + key[1]
        original, current = inputs.snapshot(root, base, source)
        if (current is None or original != current
                or hashlib.sha256(current).hexdigest() != row['sha256']):
            return False
    return True


def final_hash_map_only(before, after):
    """Repair digest values in the exact combined acceptance inventory.

    A prior malformed hex digest is not execution evidence, but correcting it
    does not change the referenced implementation. The current full acceptance
    validator always runs and checks exact paths and actual source hashes.
    """
    left, right = inputs.document(before), inputs.document(after)
    if set(left) != {'files'} or set(right) != {'files'}:
        return False
    left, right = left['files'], right['files']
    if not isinstance(left, dict) or not isinstance(right, dict) or left.keys() != right.keys():
        return False
    return (all(isinstance(v, str) and re.fullmatch('[0-9a-f]{1,64}', v) for v in left.values())
            and all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in right.values()))


def metadata_only(root, base, path, before, after):
    if path in SCRIPT_COMMANDS:
        # Removed/empty drivers do not qualify. The new explicit Windows
        # inventory helper is allowed only alongside its mandatory validator.
        return bool(after and (before or path == 'scripts/cpu/cpu_boundary_windows.py'))
    if path == 'security/cpu-acceleration-boundary.toml':
        return cpu_inventory_only(root, base, before, after)
    if path == 'scripts/hash/final-acceptance-hashes.toml':
        return final_hash_map_only(before, after)
    return False
