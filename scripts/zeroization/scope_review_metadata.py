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
SHA2_POLICY_CHECKS = (
    'python3 scripts/sha2/check-sha2-hardened-execution.py --policy-only',
    'python3 scripts/sha2/test-sha2-hardened-execution.py',
)
NATIVE_APPROVAL_CHECKS = ('python3 scripts/release/test-native-evidence-approval.py',)
API_CHECKS = ('python3 scripts/cryptography/check-api-profiles.py',
              'python3 scripts/cryptography/test-api-profiles.py',
              'python3 scripts/hmac/test-hmac-owner-contract.py')
API_METADATA = (
    'scripts/cryptography/api_profile_model.py',
    'scripts/cryptography/api_profile_render.py',
    'scripts/cryptography/hmac_owner_contract.py',
    'scripts/cryptography/test-api-profiles.py',
)
NEW_METADATA = {'scripts/cpu/cpu_boundary_windows.py',
                'scripts/cryptography/api_profile_render.py',
                'scripts/cryptography/hmac_owner_contract.py'}
NATIVE_APPROVAL_ENTRYPOINTS = (
    'scripts/sha2/check-sha2-hardened-native-evidence.py',
    'scripts/sha1/check-sha1-hardened-native.py',
    'scripts/md5/check-md5-execution-native.py',
    'scripts/md5/check-md5-hardened-native.py',
    'scripts/sha3/check-keccak-hardened-native.py',
    'scripts/kmac/check-kmac-execution-native.py',
    'scripts/tuplehash/check-tuplehash-execution-native.py',
    'scripts/parallelhash/check-parallelhash-execution-native.py',
)
SCRIPT_COMMANDS = {
    # Inventory/registration parsers, not the direct MIR or HMAC compiler
    # drivers. Their mandatory current tests do not execute cryptography.
    **dict.fromkeys(API_METADATA, API_CHECKS),
    # These parse/check existing observations; they do not execute cryptography.
    # Approval and mutation regressions run in the current baseline instead.
    **dict.fromkeys(NATIVE_APPROVAL_ENTRYPOINTS, NATIVE_APPROVAL_CHECKS),
    'scripts/cpu/cpu_boundary_policy.py': CPU_CHECKS,
    'scripts/cpu/cpu_boundary_windows.py': CPU_CHECKS,
    'scripts/cpu/test-cpu-boundary.py': CPU_CHECKS,
    'scripts/kmac/check-kmac-codegen.sh': KMAC_CHECKS,
    'scripts/kmac/test-kmac.py': KMAC_CHECKS,
    # This module inspects source/hash/gate contracts; it never executes the
    # crypto fixture or selects Miri/Kani/ASan work. Its own regressions run now.
    'scripts/sha2/sha2_hardened_execution_policy.py': SHA2_POLICY_CHECKS,
    'scripts/sha2/test-sha2-hardened-execution.py': SHA2_POLICY_CHECKS,
}
BASE_COMMANDS = frozenset((*CPU_CHECKS, *KMAC_CHECKS, *SHA2_POLICY_CHECKS, *NATIVE_APPROVAL_CHECKS, *API_CHECKS,
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


def native_observation(path):
    """Collected output is not verifier input; evidence validators still apply.

    Exact output namespaces only, never fixture vectors, collector code,
    admission policy or executable inputs. This grants no native acceptance.
    """
    families = ('sha2-hardened', 'keccak-hardened', 'kmac-execution',
                'tuplehash-execution', 'parallelhash-execution', 'sha1-hardened',
                'md5-execution', 'md5-hardened', 'sha256-batch', 'sha512-batch',
                'keccak-batch')
    if path in {f'security/{family}-native.json' for family in families}:
        return True
    directories = tuple(f'assurance/{family}-{kind}/' for family in families
                        for kind in ('native', 'observations')) + (
                            'assurance/hardened-batch-observations/',
                            'assurance/native-observations/')
    return path.startswith(directories) and path.endswith(('.json', '.txt'))


def metadata_only(root, base, path, before, after):
    if native_observation(path):
        return True
    if path in SCRIPT_COMMANDS:
        # Removed/empty drivers do not qualify. Explicit new inventory helpers
        # are allowed only alongside their mandatory current validators.
        return bool(after and (before or path in NEW_METADATA))
    if path == 'security/cpu-acceleration-boundary.toml':
        return cpu_inventory_only(root, base, before, after)
    if path == 'scripts/hash/final-acceptance-hashes.toml':
        return final_hash_map_only(before, after)
    return False
