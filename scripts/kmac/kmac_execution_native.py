"""Commit-bound native observations; not attestation or side-channel approval."""
import hashlib
import json
from pathlib import Path
import re
import sys
import kmac_execution_policy as policy

ROOT = policy.ROOT
sys.path.insert(0, str(ROOT / 'scripts/sha2'))
import hardened_native_evidence as shared
import hardened_native_host as host

INDEX = 'security/kmac-execution-native.json'
LANES = {'linux-x86_64': ('x86_64-unknown-linux-gnu', 'X86Keccak'),
         'linux-aarch64': ('aarch64-unknown-linux-gnu', 'ArmKeccak'),
         'apple-aarch64': ('aarch64-apple-darwin', 'ArmKeccak')}
require = shared.require


def sources(root):
    names = set(('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                  'scripts/sha3/check-cshake-differential.py', 'scripts/sha3/check-sha3-bit-differential.py',
                  'scripts/sha2/hardened_native_evidence.py', 'scripts/sha2/hardened_native_host.py',
                  'scripts/sha3/check-sha3-execution.py', 'scripts/sha3/cshake_execution_regressions.py',
                  'scripts/sha3/check-keccak-hardened.py', 'scripts/sha3/keccak_hardened_policy.py'))
    tracked = set(shared.git(root, 'ls-files', '-z').decode().split('\0'))
    names.update(name for name in tracked if name.startswith('.cargo/'))
    for package in (*shared.PACKAGES, 'brynja-hash-sha3', 'brynja-mac-kmac'):
        names.add('crates/' + package + '/Cargo.toml')
        names.update(path.relative_to(root).as_posix() for path in
                     (root / 'crates' / package / 'src').rglob('*.rs'))
    names.update(name for name in tracked if name.startswith('assurance/sha3-execution/')
                 and (name.endswith('.rs') or name.endswith('Cargo.toml') or name.endswith('Cargo.lock')))
    names.update(name for name in tracked if name.startswith('crates/brynja-hash-sha3/tests/'))
    names.update(name for name in tracked if name.startswith('assurance/kmac-execution/') and
                 'target' not in name.split('/') and name.endswith(('.rs', '.toml', '.lock')))
    names.update(name for name in tracked if name.startswith('scripts/kmac/') and name.endswith('.py'))
    names.update(name for name in tracked if name.startswith('crates/brynja-mac-kmac/tests/'))
    names.update(('scripts/sha3/keccak_hardened_native.py', 'scripts/sha3/capture-keccak-hardened-native.py',
                  'scripts/sha3/check-keccak-hardened-native.py'))
    require(names <= tracked, 'native inputs must all be tracked')
    # The shared lock projection includes this SHA-3 leaf via the CPU-std edge.
    # Facade-only version bumps and unrelated docs do not invalidate native code.
    return {name: shared.source_digest(name, shared.bounded(root, name))
            for name in sorted(names)}


def record_check(record, lane, commit, expected):
    require(isinstance(record, dict) and set(record) == {
        'schema', 'commit', 'lane', 'target', 'kernel', 'cpu', 'os', 'compiler',
        'sources', 'results', 'native_attestation'}, 'Keccak artifact schema')
    require(type(record['schema']) is int and record['schema'] == 1, 'Keccak schema version')
    target, kernel = LANES[lane]
    require(record['commit'] == commit and record['lane'] == lane, 'Keccak commit/lane')
    require(record['target'] == target and record['kernel'] == kernel, 'Keccak target/kernel')
    shared.compiler(record['compiler'], target)
    require(record['sources'] == expected, 'Keccak source closure drift')
    require(record['native_attestation'] == 'operator asserts native, not QEMU', 'Keccak native attestation')
    for name in ('cpu', 'os'):
        text = record[name]
        require(isinstance(text, str) and 0 < len(text) < 1024 and text.isprintable()
                and text.strip() == text, 'Keccak host identity')
    results = record['results']
    require(isinstance(results, dict) and set(results) == {'package', 'kernel_tests'}, 'Keccak results')
    for text in results.values():
        require(isinstance(text, str) and len(text) < 65536, 'Keccak output bound')
    for mode in ('portable', 'prefer-portable', 'static', 'prefer'):
        route = 'Portable' if mode in ('portable', 'prefer-portable') else kernel
        marker = f'KMAC hardened execution oracle: PASS; mode={mode}; cases=268; kernel={route}'
        require(marker in results['package'].splitlines(), 'KMAC actual keyed public operation execution')
    if kernel == 'ArmKeccak':
        require('KMAC hardened execution oracle: PASS; mode=hosted; cases=268; kernel=ArmKeccak' in
                results['package'].splitlines(), 'KMAC hosted execution')
    require('HARDENED_KECCAK_EXECUTION: ' + kernel + '; permutations=1024' in
            results['kernel_tests'].splitlines(), 'Keccak actual kernel execution')
    require('test result: ok. 4 passed; 0 failed' in results['kernel_tests'], 'Keccak kernel lifecycle tests')


def validate(root=ROOT):
    head = shared.git(root, 'rev-parse', 'HEAD').decode().strip()
    require(not shared.git(root, 'status', '--porcelain', '--untracked-files=all').strip(), 'clean Keccak release checkout')
    raw = shared.bounded(root, INDEX).replace(b'\r\n', b'\n')
    require(int(shared.git(root, 'cat-file', '-s', head + ':' + INDEX)) <= shared.LIMIT, 'committed index bound')
    require(shared.git(root, 'show', head + ':' + INDEX).replace(b'\r\n', b'\n') == raw, 'committed Keccak index')
    index = shared.document(raw)
    require(isinstance(index, dict) and set(index) == {'schema', 'capture_commit', 'lanes'}, 'Keccak index schema')
    require(type(index['schema']) is int and index['schema'] == 1, 'Keccak index version')
    capture = index['capture_commit']
    require(isinstance(capture, str) and re.fullmatch('[a-f0-9]{40}', capture), 'KMAC native collection pending')
    shared.git(root, 'merge-base', '--is-ancestor', capture, head)
    require(isinstance(index['lanes'], dict) and set(index['lanes']) == set(LANES), 'all Keccak native lanes required')
    expected = sources(root)
    for name, digest in expected.items():
        require(int(shared.git(root, 'cat-file', '-s', capture + ':' + name)) <= shared.LIMIT, 'capture source bound')
        previous = shared.git(root, 'show', capture + ':' + name).replace(b'\r\n', b'\n')
        require(shared.source_digest(name, previous) == digest, 'Keccak capture source changed: ' + name)
    for lane, row in index['lanes'].items():
        require(isinstance(row, dict) and set(row) == {'artifact', 'sha256', 'cpu', 'reviewed'}, 'Keccak review schema')
        require(row['reviewed'] is True, 'Keccak owner review pending')
        name = row['artifact']
        require(isinstance(name, str) and re.fullmatch('assurance/kmac-execution-native/[a-z0-9_-]+[.]json', name), 'Keccak artifact path')
        raw = shared.bounded(root, name).replace(b'\r\n', b'\n')
        require(int(shared.git(root, 'cat-file', '-s', head + ':' + name)) <= shared.LIMIT, 'artifact bound')
        require(shared.git(root, 'show', head + ':' + name).replace(b'\r\n', b'\n') == raw, 'committed Keccak artifact')
        require(hashlib.sha256(raw).hexdigest() == row['sha256'], 'Keccak artifact hash')
        record = shared.document(raw)
        record_check(record, lane, capture, expected)
        require(record['cpu'] == row['cpu'], 'reviewed Keccak CPU')
    print('Hardened KMAC native evidence: PASS; project-owned, non-FIPS')
