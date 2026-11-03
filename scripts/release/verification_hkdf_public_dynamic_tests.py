"""Pin downstream dynamic check selection, instrumentation and completion."""
import copy


def validate(registry):
    selected = [c for c in registry['checks']
                if c['component'] in ('hkdf', 'legacy_hkdf')
                and c.get('category') in ('asan', 'miri') and 'public-api' in c['id']]
    assert len(selected) == 5
    for component, family, fixture, count in (
            ('hkdf', 'modern', 'hkdf-public-api', 5),
            ('legacy_hkdf', 'legacy', 'legacy-hkdf-public-api', 4)):
        for selection in ('asan', 'ownership', *(['tls'] if family == 'modern' else [])):
            miri = selection != 'asan'
            check_id = f'miri-public-api-{selection}' if miri else 'asan-public-api'
            check, = [c for c in selected if c['component'] == component and c['id'] == check_id]
            assert check['category'] == ('miri' if miri else 'asan')
            assert check['command'] == ['cargo', '+nightly-2026-09-11', *(['miri'] if miri else []),
                                       'test', '--locked', '--offline', '--manifest-path',
                                       f'assurance/{fixture}/Cargo.toml', '--lib', '--target',
                                       'x86_64-unknown-linux-gnu',
                                       *([f'tests::{selection}', '--', '--exact'] if miri else [])]
            assert check['success']['minimum_tests'] == (1 if miri else count)
            assert check['success']['exact_tests'] == (1 if miri else count)
            assert check['success']['contains'] == ['test result: ok.',
                                                  *([f'test tests::{selection}'] if miri else [])]
            assert check['inputs'] == [('miri-tools' if miri else 'asan-tools'),
                                       'hkdf-public-api-dynamic', f'hkdf-public-api-{family}']
            paths = {p for group in check['inputs'] for p in registry['groups'][group].get('paths', [])}
            assert {'Cargo.toml', 'Cargo.lock', 'assurance/hkdf-public-api-common.rs',
                    f'assurance/{fixture}/Cargo.toml', f'assurance/{fixture}/Cargo.lock',
                    f'assurance/{fixture}/src'} <= paths
            assert check['platform'] == 'linux-x86_64'
            assert check['timeout_seconds'] == 1800
            env = check['environment']
            assert env['RUSTUP_AUTO_INSTALL'] == '0'
            assert {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET',
                    'RUSTC', 'RUSTDOC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'} <= set(check['reject_environment'])
            if miri:
                assert env['MIRIFLAGS'] == '-Zmiri-report-progress=10000000'
                assert env['CARGO_TARGET_DIR'] == 'target/hkdf-public-api-miri'
                assert {'MIRIFLAGS', 'MIRI_SYSROOT', 'MIRI_BE_RUSTC', 'MIRI_REPLACE_LIBRS_IF_NOT_TEST',
                        'BRYNJA_MIRI_CASE', 'BRYNJA_MIRI_PROFILE', 'BRYNJA_MIRI_WIDTH'} <= set(check['reject_environment'])
            else:
                assert env['RUSTFLAGS'] == '-Zsanitizer=address'
                assert env['CARGO_ENCODED_RUSTFLAGS'] == ''
                assert env['ASAN_OPTIONS'] == 'detect_leaks=1:halt_on_error=1:exitcode=1'
                assert env['LSAN_OPTIONS'] == 'exitcode=23'
                assert env['CARGO_TARGET_DIR'] == 'target/hkdf-public-api-asan'
                assert {'ASAN_OPTIONS', 'LSAN_OPTIONS'} <= set(check['reject_environment'])


def negative_controls(registry):
    for check_id, section, field, value in (
            ('asan-public-api', 'environment', 'RUSTFLAGS', ''),
            ('asan-public-api', 'environment', 'ASAN_OPTIONS', 'detect_leaks=0'),
            ('asan-public-api', 'environment', 'LSAN_OPTIONS', 'exitcode=0'),
            ('asan-public-api', 'success', 'exact_tests', 3),
            ('miri-public-api-ownership', 'environment', 'MIRIFLAGS', '-Zmiri-disable-validation'),
            ('miri-public-api-ownership', 'success', 'exact_tests', 2),
            ('miri-public-api-tls', 'success', 'contains', ['test result: ok.'])):
        changed = copy.deepcopy(registry)
        check = next(c for c in changed['checks'] if c['component'] == 'hkdf' and c['id'] == check_id)
        check[section][field] = value
        try:
            validate(changed)
        except AssertionError:
            continue
        raise AssertionError('accepted weakened public dynamic binding: ' + check_id)
