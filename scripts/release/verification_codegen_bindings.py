"""Existing leaf emitted-artifact checks, with their original compiler profiles."""
import json
from pathlib import Path
from verification_assessment_bindings import ENV
from verification_cargo_bindings import BASE, CPU, SHA2, SHA3, fixture_inputs, source_inputs
from verification_miri_bindings import REJECT

DATA = Path(__file__).with_name('verification_codegen_inputs.json')
HOST = 'x86_64-unknown-linux-gnu'
ARM = 'aarch64-unknown-linux-gnu'


def definitions():
    result = {}
    for family, crate, label in [('kmac', 'brynja-mac-kmac', 'KMAC'),
                                  ('tuplehash', 'brynja-hash-tuple', 'TupleHash')]:
        path = f'scripts/{family}/check-{family}-execution-codegen.py'
        result[('python3', path)] = (BASE | {CPU, SHA3, crate}, ('1.98.1',), None,
            [f'{label} execution MIR/LLVM/assembly cleanup: PASS; 1.98.1 {HOST}',
             'Source-owned regions only; not register, spill or platform erasure'])
    for version in ('1.90.0', '1.98.1'):
        result[('python3', 'scripts/parallelhash/check-parallelhash-execution-codegen.py', '--toolchain', version)] = (
            BASE | {CPU, SHA3, 'brynja-hash-parallel', 'brynja-hash-parallel-std'}, (version,), 'parallelhash-differential',
            [f'ParallelHash execution MIR/LLVM/assembly cleanup: PASS; {version} {HOST}',
             'Source-owned storage only; not register, compiler-spill or platform erasure'])
    for family, name, packages, line in (
        ('sha2', 'sha256-batch', BASE | {CPU}, 'SHA-224/256 independent SIMD codegen: PASS; 1.98.1; ' + HOST),
        ('sha2', 'sha512-batch', BASE | {CPU}, 'SHA-512-family independent SIMD codegen: PASS; 1.98.1; ' + HOST),
        ('sha2', 'sha2-hardened-execution', BASE | {CPU, SHA2}, 'Hardened execution owned-memory MIR/LLVM/assembly: PASS; 1.98.1 ' + HOST + '; unwind enabled'),
        ('sha3', 'keccak-batch', BASE | {CPU}, 'Keccak independent SIMD codegen: PASS; 1.98.1; ' + HOST),
        ('sha3', 'keccak-hardened', BASE | {CPU, SHA3}, 'Hardened Keccak MIR/LLVM/assembly cleanup: PASS; 1.98.1 ' + HOST),
    ):
        result[('python3', f'scripts/{family}/check-{name}-codegen.py')] = (packages, ('1.98.1',), None, [line])
    result[('python3', 'scripts/sha1/check-sha1-hardened-codegen.py')] = (BASE | {'brynja-legacy-sha1'}, ('1.90.0', '1.98.1'), None,
        [f'Hardened SHA-1 MIR/LLVM/assembly: PASS; {c}; {t}; seven owned regions; kernel register boundary checked; no whole-API erasure claim'
         for c in ('1.90.0', '1.98.1') for t in (HOST, ARM)])
    result[('python3', 'scripts/md5/check-md5-execution-codegen.py')] = (BASE | {'brynja-legacy-md5'}, ('1.90.0', '1.98.1'), None,
        [f'MD5 ordinary startup/digest -> vector -> SIMD session: PASS; {c}; {t}'
         for c in ('1.90.0', '1.98.1') for t in (HOST, ARM)])
    result[('python3', 'scripts/md5/check-md5-hardened-codegen.py')] = (BASE | {'brynja-legacy-md5'}, ('1.90.0', '1.98.1'), None,
        [f'MD5 hardened MIR/LLVM/SIMD assembly: PASS; {c}; {t}; panic={p}'
         for c in ('1.90.0', '1.98.1') for t in (HOST, ARM) for p in ('abort', 'unwind')])
    return result


def build(rows):
    known = definitions()
    helpers = json.loads(DATA.read_text())
    groups = {'codegen-python': {'tools': [{'program': 'python3'}]},
        'codegen-workspace': {'toml': {'Cargo.toml': ['workspace.package.edition', 'workspace.package.rust-version',
            'workspace.lints', 'workspace.resolver', 'profile.dev', 'profile.test', 'profile.release']}}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in helpers:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed codegen command: ' + row['id'])
        packages, versions, fixture, markers = known[argv]
        key = 'codegen-' + row['id']
        groups[key] = {'paths': helpers[argv[1]], 'tools': [{'program': p, 'toolchain': c}
            for c in versions for p in ('cargo', 'rustc')]}
        source = source_inputs(groups, key + '-source', packages, 'Cargo.lock')
        if fixture:
            source += fixture_inputs(groups, fixture, key + '-fixture')
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=['codegen-python', 'codegen-workspace', key, *source],
            environment=ENV, reject_environment=REJECT, platform='linux-x86_64',
            success={'contains': markers, 'unique_lines': markers}, timeout_seconds=1800, log_bytes=16777216,
            establishes='Existing exact emitted-artifact inspection and negative mutations under the original compiler/target profiles; not a native test, fresh platform capture or whole-API erasure claim.'))
    return dict(schema=1, groups=groups, checks=checks)
