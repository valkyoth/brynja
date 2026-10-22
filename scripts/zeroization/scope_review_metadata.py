"""Exact review-only inputs, paired with mandatory current repository checks.

These are not runtime/verifier drivers. No directory-wide exemption is granted.
Production sources, build inputs and memory/proof drivers are independently
classified, and their old receipts still require unchanged execution identities.
"""
import hashlib
import json
import re
from pathlib import PurePosixPath

import scope_inputs as inputs
import scope_hmac as hmac


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
    'python3 scripts/sha2/check-sha256.py', 'python3 scripts/sha2/test-sha256.py',
    'python3 scripts/sha2/test-sha256-batch.py', 'python3 scripts/sha2/test-sha512-batch.py',
    'python3 scripts/sha3/test-keccak-batch-policy.py',
    'python3 scripts/cryptography/test-macos-legacy-resident-package.py',
    'python3 scripts/hash/check-final-acceptance.py'))

# Reviewed output-parser/diagnostic regressions only. The actual SDE driver
# remains a changed command, never a reused execution result; its mandatory
# policy/regression checks are in SHA2_POLICY_CHECKS. No timeout/LSan waiver.
DIAGNOSTIC_PAIRS = {
    'scripts/sha2/check-x86-sha512.py': (
        '8629ef3d6c14afa34eb55b7667720a2d7ca1a5d8b18724f6ff8a4e69dc2601be',
        '279646a8f63118d6a4259533eca732b21573f4add90b6f1f8f293f82e2d0b102'),
    'scripts/sha2/x86_sha512_regressions.py': (
        '16b237051d74ab6eb17da6e7e3cb45e99a765c170a50e7325debc68c8f7b1cc1',
        '0578ea68015eaf5857dfd818e5d8035665344b81dca1c2c3a1334d00cf702035'),
}
BATCH_INVENTORIES = {'scripts/sha2/sha256-batch-reviewed.json': 64,
                     'scripts/sha2/sha512-batch-reviewed.json': 128,
                     'scripts/sha3/keccak-batch-reviewed.json': 128}


def cpu_inventory_only(root, base, before, after):
    """Add/rebind inventory only; never change admission, graph or limits.

    Rebound sources stay unchanged or have an exact HMAC-only projection.
    New HMAC rows use fixed path/status pairs; their real source deltas still
    select HMAC independently. Current digests match; old entries cannot vanish.
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
        if current is None or hashlib.sha256(current).hexdigest() != row['sha256']:
            return False
        hmac_addition = (previous is None and original is None and key[0] == 'brynja-crypto-cpu-std'
                         and hmac.HOSTED_SOURCES.get(key[1]) == row['status'])
        if original != current and not hmac_addition and not hmac.source_only(source, original, current):
            return False
    return True


def batch_inventory_only(root, base, path, before, after):
    """Only add registered HMAC rows; old paths and non-digest fields stay exact.

    Every new row is bound to a real source independently selected by Git.
    Current batch/acceptance policies still verify the complete inventory.
    """
    if before is None or after is None:
        return False
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate batch review key')
            result[key] = value
        return result
    old, new = [json.loads(raw, object_pairs_hook=unique) for raw in (before, after)]
    if set(old) != {'files', 'schema', 'version'} or set(new) != set(old):
        return False
    left, right = old['files'], new['files']
    if not isinstance(left, dict) or not isinstance(right, dict) or not left.keys() <= right.keys():
        return False
    size = BATCH_INVENTORIES[path]
    if any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{' + str(size) + '}', v)
           for rows in (left, right) for v in rows.values()):
        return False
    allowed = {'crates/brynja-crypto-cpu-std/' + p for p in hmac.HOSTED_SOURCES}
    for name in list(right.keys() - left.keys()):
        if name not in allowed:
            return False
        original, current = inputs.snapshot(root, base, name)
        if original is not None or current is None:
            return False
        digest = hashlib.sha256 if size == 64 else hashlib.sha512
        if digest(current).hexdigest() != right.pop(name):
            return False
    return inputs.json_hash_binding_only(json.dumps(old).encode(), json.dumps(new).encode())


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
    if path in DIAGNOSTIC_PAIRS:
        return all(raw is not None and hashlib.sha256(raw).hexdigest() in DIAGNOSTIC_PAIRS[path]
                   for raw in (before, after))
    if path in BATCH_INVENTORIES:
        return batch_inventory_only(root, base, path, before, after)
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
