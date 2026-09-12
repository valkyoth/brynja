"""Reviewed native observations, not remote attestation or certification."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/sha2'))
import hardened_native_evidence as shared
import hardened_native_host as host

require = shared.require
INDEX = 'security/parallelhash-execution-native.json'
PACKAGES = (*shared.PACKAGES, 'brynja-hash-sha3', 'brynja-hash-parallel', 'brynja-hash-parallel-std')
LANES = {'linux-x86_64': ('x86_64-unknown-linux-gnu', 'X86Keccak'),
         'linux-aarch64': ('aarch64-unknown-linux-gnu', 'ArmKeccak'),
         'apple-aarch64': ('aarch64-apple-darwin', 'ArmKeccak')}
BASE_MODES = ('portable', 'scheduled', 'prefer', 'stream', 'stream-prefer',
              'threads-portable', 'threads-prefer')
STATIC_MODES = ('static', 'stream-static', 'threads-static')
HOSTED_MODES = ('required', 'stream-required', 'threads-required')


def digest(name, raw):
    raw = raw.replace(b'\r\n', b'\n')
    if name == 'Cargo.lock':
        data = tomllib.loads(raw.decode())
        rows = {row['name']: row for row in data['package']}
        require(len(rows) == len(data['package']), 'ambiguous ParallelHash lock graph')
        selected, pending = set(), list(PACKAGES)
        while pending:
            package = pending.pop()
            if package in selected:
                continue
            require(package in rows, 'unresolved ParallelHash native dependency')
            selected.add(package)
            pending.extend(rows[package].get('dependencies', []))
        raw = json.dumps({'version': data['version'], 'package': [rows[n] for n in sorted(selected)]},
                         sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def sources(root):
    tracked = set(shared.git(root, 'ls-files', '-z').decode().split('\0'))
    names = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
             'scripts/sha2/hardened_native_evidence.py', 'scripts/sha2/hardened_native_host.py',
             'scripts/sha3/check-cshake-differential.py', 'scripts/sha3/check-sha3-bit-differential.py'}
    names.update(name for name in tracked if name.startswith('.cargo/'))
    for package in PACKAGES:
        prefix = 'crates/' + package + '/'
        names.add(prefix + 'Cargo.toml')
        code = {name for name in tracked if name.startswith(prefix + 'src/') and name.endswith('.rs')}
        require(bool(code), 'missing native package ' + package)
        names.update(code)
        names.update(name for name in tracked if name.startswith(prefix + 'tests/'))
    prefix = 'assurance/parallelhash-differential/'
    names.update({prefix + 'Cargo.toml', prefix + 'Cargo.lock', prefix + 'src/main.rs', prefix + 'src/execution.rs'})
    names.update(name for name in tracked if name.startswith(prefix + 'src/') and name.endswith('.rs'))
    # The fixture also compiles README examples; bind their source too.
    names.update('crates/' + package + '/README.md' for package in PACKAGES[-2:])
    names.update(name for name in tracked if name.startswith('scripts/parallelhash/') and name.endswith('.py'))
    names.update('scripts/parallelhash/' + name for name in (
        'capture-parallelhash-execution-native.py', 'parallelhash_execution_native.py',
        'check-parallelhash-execution-native.py', 'check-parallelhash-execution-differential.py'))
    require(names <= tracked, 'all ParallelHash native inputs must be tracked')
    return {name: digest(name, shared.bounded(root, name)) for name in sorted(names)}


def oracle_lines(modes):
    return [f'ParallelHash execution oracle: PASS; profile={profile}; mode={mode}; cases=256'
            for profile in ('debug', 'release') for mode in modes]


def record_check(record, lane, commit, expected):
    require(lane in LANES, 'ParallelHash native lane')
    require(isinstance(record, dict) and set(record) == {
        'schema', 'commit', 'lane', 'target', 'kernel', 'cpu', 'os', 'compiler',
        'sources', 'results', 'native_attestation'}, 'ParallelHash artifact schema')
    target, kernel = LANES[lane]
    require(type(record['schema']) is int and record['schema'] == 1, 'ParallelHash schema version')
    require(record['commit'] == commit and record['lane'] == lane, 'ParallelHash commit/lane')
    require(record['target'] == target and record['kernel'] == kernel, 'ParallelHash target/kernel')
    shared.compiler(record['compiler'], target)
    require(record['sources'] == expected, 'ParallelHash source closure drift')
    require(record['native_attestation'] == 'operator asserts native, not QEMU', 'ParallelHash native attestation')
    for key in ('cpu', 'os'):
        value = record[key]
        require(isinstance(value, str) and 0 < len(value) < 1024 and value.isprintable()
                and value.strip() == value, 'ParallelHash host identity')
    results = record['results']
    required = {'baseline', 'static', 'kernel_tests'} | ({'hosted'} if kernel == 'ArmKeccak' else set())
    require(isinstance(results, dict) and set(results) == required, 'ParallelHash result coverage')
    for text in results.values():
        require(isinstance(text, str) and len(text) < 65536, 'ParallelHash result bound')
    for key, modes in (('baseline', BASE_MODES), ('static', (*BASE_MODES, *STATIC_MODES)),
                       *([('hosted', (*BASE_MODES, *HOSTED_MODES))] if kernel == 'ArmKeccak' else [])):
        lines = results[key].splitlines()
        for marker in oracle_lines(modes):
            require(lines.count(marker) == 1, 'ParallelHash exact oracle mode/profile coverage')
        require(('Required static routes: PASS' if key == 'static' else 'Required static routes: NOT REQUESTED')
                in lines, 'ParallelHash static execution')
        require(('Required native routes: PASS' if key == 'hosted' else
                 'Required native routes: NOT REQUESTED; preferred routes may be portable') in lines,
                'ParallelHash hosted execution')
    lines = results['kernel_tests'].splitlines()
    require(lines.count('HARDENED_KECCAK_EXECUTION: ' + kernel + '; permutations=1024') == 1,
            'ParallelHash actual kernel execution')
    require(any(re.fullmatch(r'test result: ok\. 4 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in .+', line)
                for line in lines), 'ParallelHash four kernel lifecycle tests')


def committed(root, head, name):
    raw = shared.bounded(root, name).replace(b'\r\n', b'\n')
    require(int(shared.git(root, 'cat-file', '-s', head + ':' + name)) <= shared.LIMIT, 'native committed object bound')
    require(shared.git(root, 'show', head + ':' + name).replace(b'\r\n', b'\n') == raw, 'committed native evidence')
    return raw


def validate(root=ROOT):
    head = shared.git(root, 'rev-parse', 'HEAD').decode().strip()
    require(not shared.git(root, 'status', '--porcelain', '--untracked-files=all').strip(), 'clean native release checkout')
    index = shared.document(committed(root, head, INDEX))
    require(isinstance(index, dict) and set(index) == {'schema', 'capture_commit', 'lanes'}, 'ParallelHash index schema')
    require(type(index['schema']) is int and index['schema'] == 1, 'ParallelHash index version')
    capture = index['capture_commit']
    require(isinstance(capture, str) and re.fullmatch('[a-f0-9]{40}', capture), 'ParallelHash native collection pending')
    shared.git(root, 'merge-base', '--is-ancestor', capture, head)
    require(isinstance(index['lanes'], dict) and set(index['lanes']) == set(LANES), 'all three ParallelHash lanes required')
    expected = sources(root)
    for name, value in expected.items():
        require(int(shared.git(root, 'cat-file', '-s', capture + ':' + name)) <= shared.LIMIT, 'capture source bound')
        require(digest(name, shared.git(root, 'show', capture + ':' + name)) == value, 'changed native input: ' + name)
    for lane, row in index['lanes'].items():
        require(isinstance(row, dict) and set(row) == {'artifact', 'sha256', 'cpu', 'reviewed'}, 'ParallelHash review schema')
        require(row['reviewed'] is True, 'ParallelHash owner review pending')
        name = row['artifact']
        require(isinstance(name, str) and re.fullmatch('assurance/parallelhash-execution-native/[a-z0-9_-]+[.]json', name), 'ParallelHash artifact path')
        raw = committed(root, head, name)
        require(hashlib.sha256(raw).hexdigest() == row['sha256'], 'ParallelHash artifact hash')
        record = shared.document(raw)
        record_check(record, lane, capture, expected)
        require(record['cpu'] == row['cpu'], 'reviewed ParallelHash CPU identity')
    print('Hardened ParallelHash native evidence: PASS; project-owned, non-FIPS')
