"""Reviewed native observations bound to their capture commit and source closure.

These are owner-reviewed observations, not remote attestation, CPU-migration
proof, side-channel certification, independent crypto review or FIPS validation.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
INDEX = 'security/sha2-hardened-native.json'
LIMIT = 4 * 1024 * 1024
LANES = {
    'linux-x86_64': ('x86_64-unknown-linux-gnu', ['X86Sha256']),
    'linux-aarch64': ('aarch64-unknown-linux-gnu', ['ArmSha256', 'ArmSha512']),
    'apple-aarch64': ('aarch64-apple-darwin', ['ArmSha256', 'ArmSha512']),
}
PACKAGES = ('brynja-core', 'brynja-hash-core', 'brynja-hash-sha2',
            'brynja-crypto-cpu', 'brynja-crypto-cpu-std')
TOOLS = ('hardened_native_evidence.py', 'hardened_native_host.py',
         'capture-sha2-hardened-native.py', 'check-sha2-hardened-native-evidence.py')


def require(condition, label):
    if not condition:
        raise ValueError('hardened native evidence: ' + label)


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, timeout=30)


def bounded(root, name):
    path = root / name
    require(not path.is_symlink() and path.is_file(), 'missing/nonregular ' + name)
    require(not any(p.is_symlink() for p in path.parents if p != root), 'symlinked parent')
    with path.open('rb') as stream:
        value = stream.read(LIMIT + 1)
    require(len(value) <= LIMIT, 'oversized ' + name)
    return value


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def document(raw):
    return json.loads(raw, object_pairs_hook=unique)


def source_digest(name, raw):
    raw = raw.replace(b'\r\n', b'\n')
    if name == 'Cargo.lock':
        data = tomllib.loads(raw.decode())
        packages = {row['name']: row for row in data['package']}
        require(len(packages) == len(data['package']), 'ambiguous lock graph')
        selected, pending = set(), list(PACKAGES)
        while pending:
            package = pending.pop()
            if package in selected:
                continue
            require(package in packages, 'unresolved native dependency')
            selected.add(package)
            pending.extend(packages[package].get('dependencies', []))
        # Facade-only version changes cannot invalidate unchanged native code.
        raw = json.dumps({'version': data['version'], 'package': [packages[n] for n in sorted(selected)]},
                         sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def sources(root):
    tracked = git(root, 'ls-files', '-z').decode().split('\0')
    names = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'assurance/policy.toml'}
    names.update('crates/brynja-hash-sha2/tests/vectors/' + name for name in
                 ('general-sha512-t-digest.txt', 'nist-bit-selected.txt'))
    names.update(name for name in tracked if name.startswith('.cargo/'))
    names.update('scripts/sha2/' + name for name in TOOLS)
    for package in PACKAGES:
        prefix = 'crates/' + package + '/'
        names.add(prefix + 'Cargo.toml')
        code = {name for name in tracked if name.startswith(prefix + 'src/') and name.endswith('.rs')}
        require(bool(code), 'missing source package ' + package)
        names.update(code)
    for fixture in ('sha2-hardened-execution', 'general-sha512-t'):
        prefix = 'assurance/' + fixture + '/'
        names.update({prefix + 'Cargo.toml', prefix + 'Cargo.lock'})
        names.update(name for name in tracked if name.startswith(prefix + 'src/') and name.endswith('.rs'))
    return {name: source_digest(name, bounded(root, name))
            for name in sorted(names)}


def compiler(text, target):
    require(isinstance(text, str) and len(text) < 2048, 'compiler identity')
    require(text.startswith('rustc 1.98.1 ') and '\nrelease: 1.98.1\n' in text
            and '\nhost: ' + target + '\n' in text, 'compiler/target mismatch')


def validate_record(record, lane, commit, expected):
    require(isinstance(record, dict) and set(record) == {
        'schema', 'capture_commit', 'lane', 'target', 'cpu', 'os', 'compiler',
        'sources', 'kernels', 'results', 'native_attestation'}, 'artifact schema')
    target, kernels = LANES[lane]
    require(type(record['schema']) is int and record['schema'] == 1, 'artifact schema version')
    require(record['capture_commit'] == commit and record['lane'] == lane, 'capture identity')
    require(record['target'] == target and record['kernels'] == kernels, 'target/kernel mismatch')
    for key in ('cpu', 'os'):
        require(isinstance(record[key], str) and 0 < len(record[key]) < 1024
                and record[key].strip() == record[key] and record[key].isprintable(), key + ' identity')
    compiler(record['compiler'], target)
    require(record['sources'] == expected, 'source closure changed; recollect evidence')
    require(record['native_attestation'] == 'operator asserts native, not QEMU', 'native attestation')
    results = record['results']
    require(isinstance(results, dict) and set(results) == {'portable', 'static', 'kernel_tests'} |
            ({'hosted'} if len(kernels) == 2 else set()), 'required execution results')
    for mode in ('portable', 'static', *(['hosted'] if len(kernels) == 2 else [])):
        text = results[mode]
        require(isinstance(text, str) and len(text) < 65536, 'bounded execution result')
        require('SHA-2 hardened execution acceptance: PASS; named=240; general=4590' in text.splitlines(), 'complete vectors')
        if mode == 'portable':
            route = 'narrow=Portable; wide=Portable'
        else:
            kind = 'Static' if mode == 'static' else 'Runtime'
            wide = kind + '(ArmSha512)' if len(kernels) == 2 else 'Portable'
            route = 'narrow=' + kind + '(' + kernels[0] + '); wide=' + wide
        require(route in text.splitlines(), 'actual selected route')
    tests = results['kernel_tests']
    require(isinstance(tests, str) and len(tests) < 65536 and 'test result: ok.' in tests, 'kernel tests')
    for kernel in kernels:
        require('HARDENED_KERNEL_EXECUTION: ' + kernel + '; blocks=512' in tests.splitlines(), 'kernel execution/KAT missing')


def validate(root=ROOT, commit=None):
    head = git(root, 'rev-parse', 'HEAD').decode().strip()
    require(commit is None or commit == head, '--commit must identify current release HEAD')
    require(not git(root, 'status', '--porcelain', '--untracked-files=all').strip(), 'release checkout must be clean')
    index_raw = bounded(root, INDEX)
    require(int(git(root, 'cat-file', '-s', head + ':' + INDEX)) <= LIMIT, 'committed index bound')
    require(git(root, 'show', head + ':' + INDEX).replace(b'\r\n', b'\n') ==
            index_raw.replace(b'\r\n', b'\n'), 'index must be committed at release HEAD')
    index = document(index_raw)
    require(isinstance(index, dict) and set(index) == {'schema', 'capture_commit', 'lanes'}, 'index schema')
    require(type(index['schema']) is int and index['schema'] == 1, 'index schema version')
    capture = index['capture_commit']
    require(isinstance(capture, str) and re.fullmatch('[0-9a-f]{40}', capture), 'native collection still pending')
    git(root, 'merge-base', '--is-ancestor', capture, head)
    require(isinstance(index['lanes'], dict) and set(index['lanes']) == set(LANES), 'all three native lanes required')
    expected = sources(root)
    # A later report/evidence-only commit is allowed; changed tested sources are not.
    for name, digest in expected.items():
        require(int(git(root, 'cat-file', '-s', capture + ':' + name)) <= LIMIT, 'capture source exceeds bound')
        raw = git(root, 'show', capture + ':' + name).replace(b'\r\n', b'\n')
        require(source_digest(name, raw) == digest, 'capture commit source mismatch: ' + name)
    for lane, row in index['lanes'].items():
        require(isinstance(row, dict) and set(row) == {'artifact', 'sha256', 'cpu', 'reviewed'}, 'lane review schema')
        require(row['reviewed'] is True, 'owner review pending')
        name = row['artifact']
        require(isinstance(name, str) and re.fullmatch('assurance/sha2-hardened-native/[a-z0-9_-]+[.]json', name), 'artifact path')
        raw = bounded(root, name).replace(b'\r\n', b'\n')
        require(int(git(root, 'cat-file', '-s', head + ':' + name)) <= LIMIT, 'committed artifact bound')
        require(git(root, 'show', head + ':' + name).replace(b'\r\n', b'\n') == raw,
                'artifact must be committed at release HEAD')
        require(hashlib.sha256(raw).hexdigest() == row['sha256'], 'artifact hash mismatch')
        record = document(raw)
        validate_record(record, lane, capture, expected)
        require(row['cpu'] == record['cpu'], 'reviewed CPU identity mismatch')
    print('Hardened SHA-2 native source/commit/route evidence: PASS; project-owned, non-FIPS')
