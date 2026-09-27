#!/usr/bin/env python3
"""Run current native test/tooling checks separately from historical CPU captures.

This is project-owned evidence, not signed remote attestation. No arbitrary
commands or imported success flags are accepted. Failed/incomplete runs cannot
write a passing receipt. These checks do not qualify new Mac/Arm execution.
"""
import os
from pathlib import Path
import subprocess

import native_review_io as io

REPORT = 'security/native-reuse/v0.24.49-checks.json'
PACKAGES = ('brynja-legacy-sha1', 'brynja-legacy-md5', 'brynja-hash-sha3',
            'brynja-mac-kmac', 'brynja-hash-tuple', 'brynja-hash-parallel',
            'brynja-hash-parallel-std')
COMMANDS = [
    ['cargo', '+1.98.1', 'test', '--locked', '--offline', '-p', package,
     '--all-features', '--lib', '--tests'] for package in PACKAGES
] + [
    ['python3', 'scripts/parallelhash/check-parallelhash.py'],
    ['python3', 'scripts/parallelhash/test-parallelhash.py'],
    ['python3', 'scripts/tuplehash/check-tuplehash-execution-package.py'],
    ['python3', 'scripts/release/test-native-metadata-carry-forward.py'],
]
# Invalid selectors must have no effect on native full-matrix tests. The
# reviewed Rust counters assert full traversal whenever cfg(miri) is false.
SELECTORS = {'BRYNJA_MIRI_CASE': 'not-a-valid-case', 'BRYNJA_MIRI_PROFILE': 'routine'}
TOOLS = ('scripts/release/native_review_checks.py', 'scripts/release/native_review_io.py')


def write_generated(root, name, raw):
    path = root / io.relative(name)
    io.require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlinked output')
    io.require(len(raw) <= io.LIMIT, 'generated output bound')
    path.write_bytes(raw)


def inputs(root, review):
    # Bind all reviewed implementation/build inputs, original test/tooling
    # exceptions, and the current check producer. No whole-HEAD coupling.
    names = {n for n in io.names(root, review['reviewed_commit']) if io.protected(n)}
    names.update(review['changes'])
    names.update(TOOLS)
    names.update(command[1] for command in COMMANDS if command[0] == 'python3')
    # Bind imported native review regressions too.
    names.update(('scripts/release/native_review_tests.py',
                  'scripts/release/native_review_carry_forward.py',
                  'scripts/release/native_review_families.py'))
    return io.fingerprint({name: io.sha(io.read(root, name)) for name in sorted(names)})


def validate_receipt(root, review, review_raw, head):
    io.require(review['verification'] == REPORT, 'unexpected verification path')
    report = io.document(io.committed(root, REPORT, head))
    io.require(set(report) == {'schema', 'review_sha256', 'inputs', 'compiler', 'environment', 'checks'},
               'verification receipt fields')
    io.require(type(report['schema']) is int and report['schema'] == 1 and
               report['review_sha256'] == io.sha(review_raw) and report['inputs'] == inputs(root, review),
               'current verification source binding')
    io.require(report['environment'] == SELECTORS and
               'release: 1.98.1' in report['compiler'].splitlines() and
               'host: x86_64-unknown-linux-gnu' in report['compiler'].splitlines(), 'verification host/options')
    io.require(isinstance(report['checks'], list) and len(report['checks']) == len(COMMANDS),
               'complete focused verification required')
    for index, (entry, command) in enumerate(zip(report['checks'], COMMANDS)):
        io.require(set(entry) == {'command', 'exit_code', 'log', 'sha256'} and
                   entry['command'] == command and type(entry['exit_code']) is int and
                   entry['exit_code'] == 0, 'failed/mismatched focused check')
        name = f'security/native-reuse/v0.24.49-check-{index:02d}.log'
        io.require(entry['log'] == name, 'focused log path')
        raw = io.committed(root, name, head)
        io.require(raw and io.sha(raw) == entry['sha256'], 'focused log hash')


def main():
    from native_review_carry_forward import REVIEW, schema, check_changes, check_protected
    root = io.ROOT
    raw = io.read(root, REVIEW)
    review = io.document(raw)
    schema(review)
    check_changes(root, review)
    head = io.git(root, 'rev-parse', 'HEAD').decode().strip()
    check_protected(root, review, head)
    before = inputs(root, review)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith(('BRYNJA_', 'CARGO_', 'RUST', 'MIRI')):
            env.pop(key)
    env.update(SELECTORS)
    compiler = subprocess.check_output(['rustc', '+1.98.1', '-vV'], env=env, text=True)
    io.require('host: x86_64-unknown-linux-gnu' in compiler.splitlines(), 'focused evidence requires Linux x86')
    results = []
    for index, command in enumerate(COMMANDS):
        print('CURRENT_NATIVE_REVIEW_CHECK: ' + ' '.join(command), flush=True)
        # Named per-check logs survive cargo clean. This program never edits an
        # original native artifact. A command timeout/error aborts the receipt.
        result = subprocess.run(command, cwd=root, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=1800)
        io.require(result.returncode == 0, 'focused check failed: ' + result.stdout[-6000:].decode(errors='replace'))
        io.require(0 < len(result.stdout) <= io.LIMIT, 'focused log output bound')
        name = f'security/native-reuse/v0.24.49-check-{index:02d}.log'
        # Canonical LF and one final newline; preserve every nonempty output
        # line. Original native capture artifacts are never rewritten.
        output = io.normalized(result.stdout).rstrip(b'\n') + b'\n'
        write_generated(root, name, output)
        results.append({'command': command, 'exit_code': 0, 'log': name,
                        'sha256': io.sha(output)})
    io.require(inputs(root, review) == before and io.read(root, REVIEW) == raw and
               io.git(root, 'rev-parse', 'HEAD').decode().strip() == head, 'inputs changed during focused run')
    report = {'schema': 1, 'review_sha256': io.sha(raw), 'inputs': before,
              'compiler': compiler, 'environment': SELECTORS, 'checks': results}
    write_generated(root, REPORT, (io.json.dumps(report, indent=2) + '\n').encode())
    print('Current native test/tooling review: PASS; original platform captures unchanged')


if __name__ == '__main__':
    main()
