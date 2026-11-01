"""Exact HMAC compiler profiles and checker suites; no native qualification.

The maintained helper lists are data, not runtime import/test discovery. Existing
drivers still enforce their own graph populations and artifact assumptions.
"""
import json
from pathlib import Path
from verification_assessment_bindings import ENV
from verification_cargo_bindings import fixture_inputs
from verification_miri_bindings import REJECT

DATA = Path(__file__).with_name('verification_compiler_inputs.json')
TARGETS = ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'aarch64-apple-darwin')


def marker(kind, compiler, target, panic, option=False):
    profile = f'{compiler}; {target}; panic={panic}; '
    return {
        'hmac-hosted': 'HMAC hosted capture/admission/storage/input/output/checkpoints/transaction/cleanup-dispatch: PASS; ' + profile +
            '48 host consumers, 48 loan probes, 24 executors; full hosted qualification pending',
        'legacy-hmac-hosted': 'Legacy HMAC lifecycle/owners, streaming I/O, checkpoints, MD5 health/report/lane/control/decision/tag-copy/returned-owner provenance: PASS; ' + profile +
            f'simd={not option}; bounded host/worker chain, setup errors, public decisions and output loans reconciled; not native qualification',
        'hmac-execution': 'HMAC accelerated owner dispatch: PASS; ' + profile +
            '12 cancellation and 12 update/error/unwind consumers, static/runtime and retained/empty; actual hash-core and CPU-scratch helper graphs; not whole-frame erasure',
        'hmac-static': 'HMAC static-only retained/wrapper cleanup: PASS; ' + profile +
            '24 cancellation/update and 72 finalizer scratch/handoff consumers; consuming Engine/adapter and 12 constructor owner graphs checked; not whole-frame erasure',
        # These drivers append artifact-dependent diagnostic counts. Bind each
        # profile prefix once; the driver validates the actual bodies/counts.
        'legacy-hmac-execution': 'Legacy SHA-1 HMAC retained caller graphs: PASS; ' + profile,
        'legacy-hmac-md5': 'Legacy HMAC-MD5 row cleanup: PASS; ' + profile + f'simd={option}; ',
    }[kind]


def definitions():
    data = json.loads(DATA.read_text())
    result = {}
    for kind in ('hmac-hosted', 'legacy-hmac-hosted', 'hmac-execution', 'hmac-static',
                 'legacy-hmac-execution', 'legacy-hmac-md5'):
        legacy = kind.startswith('legacy-')
        directory = 'scripts/legacy-hmac/' if legacy else 'scripts/hmac/'
        script = directory + 'check-' + kind + '-cleanup.py'
        fixture = ('hmac-execution' if kind == 'hmac-static' else kind) + '-cleanup'
        targets = TARGETS if legacy or kind == 'hmac-hosted' else TARGETS[:2]
        flag = '--generic' if kind == 'legacy-hmac-hosted' else '--simd' if kind == 'legacy-hmac-md5' else None
        for target in targets:
            compilers = ('1.99.1',) if legacy and target != TARGETS[0] else ('1.90.0', '1.99.1')
            args = [] if target == TARGETS[0] else ['--target', target]
            if len(compilers) == 1:
                args += ['--toolchain', '1.99.1']
            for option in ((False, True) if flag else (False,)):
                command = ('python3', script, *args, *([flag] if option else []))
                markers = [marker(kind, c, target, p, option) for c in compilers for p in ('abort', 'unwind')]
                dynamic = kind in ('legacy-hmac-execution', 'legacy-hmac-md5')
                success = {'contains': markers, 'unique_prefixes' if dynamic else 'unique_lines': markers}
                result[command] = dict(**data[script], fixture=fixture, compilers=compilers, success=success)
    for script, spec in data.items():
        if '/test-' not in script:
            continue
        modern = script.startswith('scripts/hmac/')
        fixture = ('hmac' if modern else 'legacy-hmac') + '-execution-cleanup'
        compilers = ('1.90.0', '1.99.1') if script.endswith('/test-hmac-execution-cleanup.py') else ('1.99.1',)
        result[('python3', script)] = dict(**spec, fixture=fixture, compilers=compilers,
            success={'contains': [f'\nRan {spec["tests"]} tests in '], 'unique_lines': ['OK']})
    return result


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    groups = {'compiler-python': {'tools': [{'program': 'python3'},
        {'program': 'c++filt'}, {'program': 'llvm-cxxfilt', 'optional': True}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed compiler command: ' + row['id'])
        spec = known[argv]
        key = 'compiler-' + row['id']
        paths = list(spec['helpers'])
        if spec.get('tests'):
            # Existing mutation fixtures edit literal manifest text.
            paths += ['assurance/' + spec['fixture'] + '/' + f for f in ('Cargo.toml', 'Cargo.lock')]
            leaf = 'brynja-mac-hmac' if row['families'] == ['hmac'] else 'brynja-legacy-hmac'
            paths.append('crates/' + leaf + '/Cargo.toml')
        groups[key] = {'paths': paths, 'tools': [{'program': p, 'toolchain': c}
            for c in spec['compilers'] for p in ('cargo', 'rustc')],
            'toml': {'Cargo.toml': ['workspace.package.edition', 'workspace.package.rust-version',
                                   'workspace.package.license', 'workspace.package.repository', 'workspace.lints']}}
        source = fixture_inputs(groups, spec['fixture'], key + '-source')
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=['compiler-python', key, *source], environment=ENV,
            reject_environment=REJECT, platform='linux-x86_64', success=spec['success'],
            timeout_seconds=3600, log_bytes=16777216,
            establishes='Existing selected emitted-code profiles or checker mutations; no native backend execution, whole-frame erasure, hosted OS cleanup or independent review is claimed.'))
    return dict(schema=1, groups=groups, checks=checks)
