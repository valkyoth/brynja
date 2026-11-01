"""Explicit legacy source-policy selectors, not new assurance requirements.

Review/gate text is an input only where the original policy reads it. The two
optimized-invariant checks execute their existing two Rust tests; the acceleration
regression selector compiles model/Clippy mutants with positive controls. Other
registrations inspect source/models only. No checker is imported by this exporter
or by a status scan.
"""
import json
from pathlib import Path
from verification_assessment_bindings import ENV
from verification_cargo_bindings import source_inputs, fixture_inputs
from verification_miri_bindings import BASE, REJECT

DATA = Path(__file__).with_name('verification_legacy_policy_inputs.json')


def definitions():
    result = {}
    for family, title in [('md5', 'MD5'), ('sha1', 'SHA-1')]:
        result[('python3', f'scripts/{family}/test-{family}.py')] = (
            family, [f'{title} source policy rejects 56 structural regressions'], None)
        result[('python3', f'scripts/{family}/check-{family}.py')] = (
            family, [f'isolated legacy {title} source and mandatory cleanup policy: PASS'], 'compiled')
    for family, stem, key, markers in [
        ('md5', 'md5-cpu', 'md5-cpu', ['MD5 batch/SIMD policy rejects 36 ownership, budget, kernel, admission and dynamic-analysis regressions']),
        ('md5', 'md5-execution', 'md5-execution', ['MD5 operational authority/transaction policy: 64 mutations rejected']),
        ('sha1', 'sha1-cpu', 'sha1-cpu', ['SHA-1 CPU rejects 60 authority, feature, quarantine, lifecycle and isolation mutations',
                                      'SHA-1 CPU rejects README content and line-ending review drift']),
        ('sha2', 'sha512-t-contract', 'sha512-t-contract', []),
    ]:
        result[('python3', f'scripts/{family}/test-{stem}.py')] = (key, markers, 'unittest' if not markers else None)
    result[('python3', 'scripts/sha2/check-sha512-t-contract.py')] = ('sha512-t-contract', [
        'General SHA-512/t contract: PASS; 510 parameter descriptors, 14 operation groups',
        'Contract model gate; hashing/lifecycle/package execution is separate; final closure pending v0.24.29; no FIPS/CPU admission'], None)
    result[('python3', 'scripts/cpu/check-acceleration-availability.py')] = ('acceleration-availability', [
        'Acceleration availability contract: PASS; 11 kernels, 29 identities, zero high-level family activations'], None)
    result[('python3', 'scripts/cpu/test-acceleration-availability.py')] = ('acceleration-availability', [
        'Acceleration contract rejects 20 policy/source and 18 compiled regressions',
        'Dedicated Clippy gate rejects 6 driver regressions and 5 compiled forbidden patterns'], 'model-mutants')
    return result


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    declared = json.loads(DATA.read_text())
    groups = {'legacy-policy-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed legacy policy selector: ' + row['id'])
        scope, markers, mode = known[argv]
        key = 'legacy-policy-' + row['id']
        groups[key] = {'paths': sorted(set([argv[1], *declared[scope]['paths']]))}
        inputs = ['legacy-policy-python', key]
        env = dict(ENV)
        success = {'contains': markers, 'unique_lines': markers}
        if mode == 'unittest':
            success = {'contains': ['\nRan 7 tests in '], 'unique_lines': ['OK']}
        if mode == 'compiled':
            groups[key]['tools'] = [{'program': p, 'toolchain': '1.99.1'} for p in ('cargo', 'rustc')]
            groups[key]['toml'] = {'Cargo.toml': ['workspace.package.edition', 'workspace.package.rust-version',
                'workspace.lints', 'workspace.resolver', 'profile.release']}
            inputs += source_inputs(groups, key + '-source', BASE | {'brynja-legacy-' + scope}, 'Cargo.lock')
            env['RUSTUP_TOOLCHAIN'] = '1.99.1'
            success.update(minimum_tests=2, exact_tests=2)
        if mode == 'model-mutants':
            groups[key]['tools'] = [{'program': p, 'toolchain': '1.99.1'}
                                   for p in ('cargo', 'rustc', 'clippy-driver')]
            inputs += fixture_inputs(groups, 'acceleration-contract', key + '-model')
            env['RUSTUP_TOOLCHAIN'] = '1.99.1'
        establishes = {
            'compiled': 'Existing source policy plus two optimized offset-invariant tests.',
            'model-mutants': 'Existing acceleration selection/lifecycle model: policy/source mutations, '
                             'debug/release compiled mutants and dedicated Clippy mutations, with positive '
                             'controls. No cryptographic backend execution or native qualification.',
        }.get(mode, 'Existing source-policy or admission-model assertions only; no cryptographic execution.')
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=inputs, environment=env, reject_environment=REJECT,
            success=success, timeout_seconds=3600 if mode == 'model-mutants' else 300, log_bytes=16777216,
            establishes=establishes +
                        ' Original review/gate text affects this policy row only, not previous runtime/proof results.'))
    return dict(schema=1, groups=groups, checks=checks)
