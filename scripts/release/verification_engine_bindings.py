"""Exact portable HMAC caller-codegen selections; no runtime/native claims."""

SHARED = ['scripts/hmac/' + name + '.py' for name in (
    'hmac_engine_codegen', 'hmac_engine_update', 'hmac_engine_scratch',
    'hmac_engine_final', 'hmac_constructor_state')]
MODERN = SHARED + ['scripts/hmac/' + name + '.py' for name in (
    'hmac_engine_construct', 'hmac_engine_construct_state', 'hmac_verifiers')]
LEGACY = SHARED + ['scripts/legacy-hmac/' + name + '.py' for name in (
    'legacy_hmac_engine_codegen', 'legacy_hmac_engine_scratch',
    'legacy_hmac_engine_final', 'legacy_hmac_engine_construct',
    'legacy_hmac_timing_runner', 'legacy_hmac_timing')]


def marker(family, compiler, target, panic):
    if family == 'hmac':
        return (f'HMAC caller cleanup dispatch: PASS; {compiler}; {target}; panic={panic}; '
                '12 cancellations, 12 update/error consumers, 84 byte/bit scratch consumers, '
                '72 consuming-finalizer owner graphs, 12 constructor owner graphs; '
                'accelerated/hosted qualification pending; no whole-frame erasure claim')
    return (f'Legacy HMAC caller dispatch: PASS; {compiler}; {target}; panic={panic}; '
            'two cancellations, two update/error/unwind consumers, fourteen scratch consumers, '
            'twelve finalizer and two constructor owner graphs; accelerated/hosted paths separate')


def definitions():
    result = {}
    for family, directory, name, helpers, tests in (
        ('hmac', 'scripts/hmac/', 'hmac', MODERN, 27),
        ('legacy_hmac', 'scripts/legacy-hmac/', 'legacy-hmac', LEGACY, 9),
    ):
        driver = directory + 'check-' + name + '-engine-cleanup.py'
        paths = [*helpers, 'scripts/repository/facade_cargo_environment.py']
        targets = [('x86_64-unknown-linux-gnu', (), ('1.90.0', '1.99.1'))]
        if family == 'hmac':
            targets += [('aarch64-unknown-linux-gnu', ('--target', 'aarch64-unknown-linux-gnu'), ('1.90.0', '1.99.1'))]
        else:
            targets += [(target, ('--target', target, '--toolchain', '1.99.1'), ('1.99.1',))
                        for target in ('aarch64-unknown-linux-gnu', 'aarch64-apple-darwin')]
        for target, args, compilers in targets:
            markers = [marker(family, compiler, target, panic)
                       for compiler in compilers for panic in ('abort', 'unwind')]
            result[('python3', driver, *args)] = dict(
                paths=paths, fixture=name + '-engine-cleanup', compilers=compilers,
                success={'contains': markers, 'unique_lines': markers},
                establishes='Portable caller ownership and scratch-dispatch emitted-code checks for the selected compiler/target/panic profiles; no native, accelerated, hosted or whole-frame erasure qualification.')
        baseline = marker(family, '1.99.1', 'x86_64-unknown-linux-gnu', 'unwind')
        # These mutation suites edit raw fixture TOML text, not just parsed fields.
        test_paths = [*paths, driver, 'assurance/' + name + '-engine-cleanup/Cargo.toml',
                      'assurance/' + name + '-engine-cleanup/Cargo.lock']
        if family == 'hmac':
            test_paths += ['scripts/hmac/hmac_constructor_tests.py']
        result[('python3', directory + 'test-' + name + '-engine-cleanup.py')] = dict(
            paths=test_paths, fixture=name + '-engine-cleanup', compilers=('1.99.1',),
            success={'contains': [baseline, f'\nRan {tests} tests in '], 'unique_lines': [baseline, 'OK']},
            establishes='Existing portable caller and constructor mutation suite, including inherited constructor tests; emitted-code regressions, not native or whole-frame erasure qualification.')
    return result
