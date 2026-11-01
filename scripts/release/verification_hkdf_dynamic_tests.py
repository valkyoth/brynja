"""Exact scope and instrumentation for new HKDF dynamic-analysis bindings."""
import copy


def validate(registry, closures):
    selected = [c for c in registry['checks'] if c['component'] in ('hkdf', 'legacy_hkdf')
                and c.get('category') in ('miri', 'asan')]
    assert len(selected) == 8
    for component, package, harness, lifecycle, fault, vectors, faults in (
        ('hkdf', 'brynja-crypto', 'hkdf_derivation', 'disjoint_allocation_and_unwind_cleanup',
         'hkdf::derive::tests::hkdf_fault_tls_label_scratch_clears', 8, 5),
        ('legacy_hkdf', 'brynja-legacy-hkdf', 'derivation', 'disjoint_storage_and_drop_during_unwind',
         'tests::hkdf_fault_expand_clears_output_and_retains_prk', 6, 4),
    ):
        for check_id, selector, count in (
            ('asan-derivation', ['--test', harness], vectors),
            ('asan-fault-cleanup', ['--lib', 'hkdf_fault_'], faults),
            ('miri-lifecycle', ['--test', harness, lifecycle, '--', '--exact'], 1),
            ('miri-fault-cleanup', ['--lib', fault, '--', '--exact'], 1),
        ):
            rows = [c for c in selected if c['component'] == component and c['id'] == check_id]
            assert len(rows) == 1
            check = rows[0]
            miri = check_id.startswith('miri-')
            assert check['category'] == ('miri' if miri else 'asan')
            assert check['command'] == ['cargo', '+nightly-2026-09-11', *(['miri'] if miri else []),
                                        'test', '--locked', '--offline', '--target',
                                        'x86_64-unknown-linux-gnu', '-p', package,
                                        '--no-default-features', *selector]
            assert check['success']['minimum_tests'] == count
            assert check['success']['exact_tests'] == count
            assert 'test result: ok.' in check['success']['contains']
            assert check['platform'] == 'linux-x86_64'
            assert check['timeout_seconds'] == 1800
            assert ('miri-tools' if miri else 'asan-tools') in check['inputs']
            paths = {p for group in check['inputs'] if group in registry['groups']
                     for p in registry['groups'][group].get('paths', [])}
            for dependency in closures[package] | {package}:
                assert f'crates/{dependency}/src' in paths
            if '--test' in selector:
                assert f'crates/{package}/tests/{harness}.rs' in paths
            env = check['environment']
            assert env['RUSTUP_AUTO_INSTALL'] == '0'
            assert {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC', 'RUSTC_WRAPPER',
                    'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET'} <= set(check['reject_environment'])
            if miri:
                assert env['MIRIFLAGS'] == '-Zmiri-report-progress=10000000'
                assert env['CARGO_TARGET_DIR'] == 'target/hkdf-miri'
                assert {'MIRIFLAGS', 'MIRI_SYSROOT', 'MIRI_BE_RUSTC',
                        'MIRI_REPLACE_LIBRS_IF_NOT_TEST'} <= set(check['reject_environment'])
                # Progress notes can split the test-name/ok line. Exact test
                # selection, process success and exact population still bind
                # the result; do not depend on merged stdout/stderr adjacency.
                signal = 'test ' + (lifecycle if check_id == 'miri-lifecycle' else fault)
                assert signal in check['success']['contains']
                interleaved = (signal + ' ... note: progress report: current operation\n'
                               '  so far, 10000000 basic blocks have been executed\n'
                               'ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; '
                               '0 measured; 0 filtered out; finished in 1.00s\n')
                assert all(text in interleaved for text in check['success']['contains'])
            else:
                assert env['RUSTFLAGS'] == '-Zsanitizer=address'
                assert env['CARGO_ENCODED_RUSTFLAGS'] == ''
                assert env['ASAN_OPTIONS'] == 'detect_leaks=1:halt_on_error=1:exitcode=1'
                assert env['LSAN_OPTIONS'] == 'exitcode=23'
                assert env['CARGO_TARGET_DIR'] == 'target/hkdf-asan'


def negative_controls(registry, closures):
    for check_id, section, field, value in (
        ('asan-derivation', 'environment', 'RUSTFLAGS', ''),
        ('asan-fault-cleanup', 'environment', 'ASAN_OPTIONS', 'detect_leaks=0'),
        ('miri-lifecycle', 'environment', 'MIRIFLAGS', '-Zmiri-disable-validation'),
        ('miri-fault-cleanup', 'success', 'exact_tests', 0),
        ('miri-lifecycle', 'success', 'contains',
         ['test result: ok.', 'test disjoint_allocation_and_unwind_cleanup ... ok']),
    ):
        changed = copy.deepcopy(registry)
        row = next(c for c in changed['checks'] if c['component'] == 'hkdf' and c['id'] == check_id)
        row[section][field] = value
        try:
            validate(changed, closures)
        except AssertionError:
            continue
        raise AssertionError('accepted weakened dynamic check: ' + check_id)
