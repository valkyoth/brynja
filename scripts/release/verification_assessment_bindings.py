"""Explicit existing proof-inventory, vector and scratch-codegen commands.

This is registration data, not test discovery/execution or a dependency resolver.
Compiler checks inspect emitted code; they do not claim native execution.
"""
import json
from pathlib import Path
from verification_cargo_bindings import fixture_inputs, LEGACY
from verification_miri_bindings import REJECT
from verification_engine_bindings import definitions as engine_definitions
from verification_md5_checker_bindings import definitions as md5_checker_definitions

ENV = {'PYTHONOPTIMIZE': '0', 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1',
       'RUSTUP_AUTO_INSTALL': '0', 'CARGO_NET_OFFLINE': 'true'}
SETUP = ['scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py']
CSHAKE = ['scripts/sha3/check-cshake-differential.py', 'scripts/sha3/check-sha3-bit-differential.py']
MODES = ('portable', 'scheduled', 'prefer', 'stream', 'stream-prefer', 'threads-portable', 'threads-prefer')
SCRATCH = {
    'hmac': ('scripts/hmac/', 'hmac', ['scripts/hmac/hmac_cleanup_codegen.py', *SETUP]),
    'legacy_hmac': ('scripts/legacy-hmac/', 'legacy-hmac', [
        'scripts/legacy-hmac/legacy_hmac_cleanup_codegen.py',
        'scripts/legacy-hmac/legacy_hmac_timing_runner.py',
        'scripts/legacy-hmac/legacy_hmac_timing.py',
        'scripts/hmac/hmac_cleanup_codegen.py', 'scripts/repository/facade_cargo_environment.py']),
}


def definitions():
    """Exact argv allowlist with existing completion signals, never write mode."""
    result = engine_definitions()
    result.update(md5_checker_definitions())
    for family, (directory, name, helpers) in SCRATCH.items():
        targets = [('x86_64-unknown-linux-gnu', (), ('1.90.0', '1.99.1'))]
        if family == 'hmac':
            targets += [('aarch64-unknown-linux-gnu', ('--target', 'aarch64-unknown-linux-gnu'), ('1.90.0', '1.99.1'))]
        else:
            targets += [(target, ('--target', target, '--toolchain', '1.99.1'), ('1.99.1',))
                        for target in ('aarch64-unknown-linux-gnu', 'aarch64-apple-darwin')]
        for target, args, compilers in targets:
            markers = [scratch_marker(family, compiler, target, panic)
                       for compiler in compilers for panic in ('abort', 'unwind')]
            result[('python3', directory + 'check-' + name + '-cleanup.py', *args)] = dict(
                paths=helpers, fixture=name + '-cleanup', compilers=compilers,
                success={'contains': markers, 'unique_lines': markers},
                establishes='Five existing scratch probes per compiler/panic profile; emitted-code inspection only, not whole-composition or native qualification.')
        marker = scratch_marker(family, '1.99.1', 'x86_64-unknown-linux-gnu', 'unwind')
        count = 6 if family == 'hmac' else 5
        result[('python3', directory + 'test-' + name + '-cleanup.py')] = dict(
            paths=[*helpers, directory + 'check-' + name + '-cleanup.py'],
            fixture=name + '-cleanup', compilers=('1.99.1',),
            success={'contains': [marker, f'\nRan {count} tests in '], 'unique_lines': [marker, 'OK']},
            establishes='Existing real-emission and compiled scratch-cleanup mutations only; no native or whole-composition claim.')
    result[('python3', 'scripts/hmac/check-hmac-kani.py', '--policy-only')] = dict(
        paths=[*SETUP, 'assurance/hmac-policy/Cargo.toml', 'assurance/hmac-policy/Cargo.lock',
               'assurance/hmac-policy/src/lib.rs'],
        markers=['HMAC Kani inventory: 2 runtime-predicate proofs; NOT executed'],
        establishes='Dependency-free proof-fixture shape and declared harness population only; no Kani execution.')
    result[('python3', 'scripts/legacy-hmac/check-legacy-hmac-kani.py', '--policy-only')] = dict(
        paths=[*SETUP, 'scripts/legacy-hmac/legacy_hmac_verifiers.py',
               'assurance/legacy-hmac-policy/Cargo.toml', 'assurance/legacy-hmac-policy/Cargo.lock',
               'assurance/legacy-hmac-policy/src/lib.rs'],
        toml={f'crates/{package}/Cargo.toml': ['package.version'] for package in sorted(LEGACY | {'brynja-legacy-hmac'})},
        markers=['Legacy HMAC Kani inventory: 2 invalid-tag-width proofs; NOT executed'],
        establishes='Declared proof harness constraints and dependency identities only; no constructor or Kani execution.')
    result[('python3', 'scripts/sha3/cshake_execution_vectors.py')] = dict(
        paths=[*CSHAKE, 'crates/brynja-hash-sha3/tests/vectors/cshake-execution.txt'],
        markers=['cSHAKE execution: 628 independent/official vectors reproduced'],
        establishes='Existing Python oracle reproduces stored vectors; no Rust, CPU backend or native execution.')
    markers = [f'ParallelHash execution oracle: PASS; profile={profile}; mode={mode}; cases=256'
               for profile in ('debug', 'release') for mode in MODES]
    markers += ['Required native routes: NOT REQUESTED; preferred routes may be portable',
                'Required static routes: NOT REQUESTED']
    result[('python3', 'scripts/parallelhash/check-parallelhash-execution-differential.py')] = dict(
        paths=[*CSHAKE, 'scripts/parallelhash/check-parallelhash-differential.py'],
        fixture='parallelhash-differential', compilers=('1.99.1',), markers=markers,
        establishes='Existing 256-case independent oracle across seven execution modes and debug/release; no required native/static route qualification.')
    result[('python3', 'scripts/sha3/test-keccak-batch-asan.py')] = dict(
        paths=['scripts/sha3/check-keccak-batch-asan.py', 'scripts/sha3/keccak_batch_codegen.py'],
        success={'contains': ['\nRan 2 tests in '], 'unique_lines': ['OK']},
        establishes='Mocked sanitizer orchestration, failure and CPU-admission regressions only; no ASan/native execution.')
    declared = json.loads(Path(__file__).with_name('verification_policy_inputs.json').read_text())
    for family, title in [('kmac', 'KMAC hardened'), ('tuplehash', 'TupleHash')]:
        result[('python3', f'scripts/{family}/check-{family}-execution.py')] = dict(
            paths=declared[family + '-execution']['paths'],
            patterns=[f'scripts/{family}/*execution*.py'],
            fixture=family + '-execution', compilers=('1.98.1',),
            markers=[f'{title} execution oracle: PASS; mode={mode}; cases=268; kernel=Portable'
                     for mode in ('portable', 'prefer-portable')],
            establishes='Existing 12 official plus 256 arbitrary-bit oracle cases in portable and '
                        'prefer-portable modes, malformed-request rejection, and KMAC production-type '
                        'comparison where applicable. No native, emulated or sanitizer mode selected. '
                        'Historical source/gate policy inputs affect this check only, not other records.')
    return result


def scratch_marker(family, compiler, target, panic):
    prefix, suffix = (('HMAC scratch cleanup', '5 probes; not whole-composition qualification') if family == 'hmac'
                      else ('Legacy HMAC Scratch cleanup', 'five probes; caller/MD5-row/worker qualification separate'))
    return f'{prefix}: PASS; {compiler}; {target}; panic={panic}; {suffix}'


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    groups = {'assessment-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed assessment command/environment: ' + row['id'])
        spec = known[argv]
        key = 'assessment-' + row['id']
        groups[key] = dict(paths=[argv[1], *spec['paths']], toml=spec.get('toml', {}),
                           patterns=spec.get('patterns', []))
        inputs = ['assessment-python', key]
        env = dict(ENV)
        if spec.get('fixture'):
            groups[key]['tools'] = [{'program': program, 'toolchain': compiler}
                                    for compiler in spec['compilers'] for program in ('cargo', 'rustc')]
            # Explicit default for the ParallelHash wrapper's unqualified cargo.
            env['RUSTUP_TOOLCHAIN'] = spec['compilers'][-1]
            inputs += fixture_inputs(groups, spec['fixture'], key + '-source')
            groups[key]['toml']['Cargo.toml'] = ['workspace.package.edition', 'workspace.package.rust-version', 'workspace.lints']
        success = spec.get('success') or dict(contains=spec['markers'], unique_lines=spec['markers'])
        check = dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
                     command=list(argv), cwd='.', inputs=inputs, environment=env, reject_environment=REJECT,
                     success=success, timeout_seconds=1800 if spec.get('fixture') else 300,
                     log_bytes=16777216, establishes=spec['establishes'])
        if spec.get('fixture'):
            check['platform'] = 'linux-x86_64'
        checks.append(check)
    return dict(schema=1, groups=groups, checks=checks)
