"""Existing HMAC-MD5 compiler-checker regressions, not native executions.

Explicit helper closure: all suites import the same MD5 driver. Its shared
checkers are inputs; unrelated hosted checkers and modern HMAC runtime are not.
No imports of checkers, test discovery, or crypto execution occur here.
"""

DIRECTORY = 'scripts/legacy-hmac/'
DRIVER = DIRECTORY + 'check-legacy-hmac-md5-cleanup.py'
FIXTURE = 'legacy-hmac-md5-cleanup'
COUNTS = {
    'caller': 10, 'cleanup': 10, 'consumer-internal': 10, 'consumer-return': 8,
    'descriptors': 8, 'handoff': 5, 'inner-owner': 6, 'inner-report': 7,
    'keys': 11, 'normalization': 13, 'outer': 7, 'output-path': 9,
    'pads': 10, 'phases': 8, 'results': 10, 'return-metadata': 12,
    'setup-reports': 11, 'teardown': 13,
}
SINGLE_COMPILER = {'cleanup', 'handoff', 'phases'}
HELPERS = [DIRECTORY + 'legacy_hmac_md5_' + suffix + '.py' for suffix in (
    'admission', 'candidates', 'comparison', 'consumer_return', 'descriptors',
    'error_flow', 'fence', 'handoff', 'initialization', 'inner_owner', 'inner_report',
    'key_model', 'keys', 'normalization', 'normalization_bits', 'normalization_flow',
    'normalization_return', 'outer', 'outer_model', 'outer_result', 'output_views',
    'pad_model', 'pads', 'phases', 'quarantine', 'report_return', 'reports', 'results',
    'return_header', 'return_layout', 'return_paths', 'return_writes', 'row_contracts',
    'row_origins', 'rows', 'secret_consumer', 'setup', 'teardown', 'truncation',
)] + [DIRECTORY + 'legacy_hmac_' + suffix + '.py' for suffix in (
    'engine_codegen', 'engine_final', 'engine_scratch', 'execution_admission',
    'execution_admission_contracts', 'execution_final', 'execution_handoff',
    'execution_iterator', 'execution_state', 'timing', 'timing_runner',
)] + ['scripts/hmac/hmac_' + suffix + '.py' for suffix in (
    'callee_identity', 'constructor_state', 'engine_codegen', 'engine_final',
    'engine_scratch', 'engine_update', 'execution_admission_contracts',
    'execution_drop', 'execution_final_contracts', 'execution_iterator',
)] + ['scripts/repository/facade_cargo_environment.py']


def definitions():
    result = {}
    for name, count in COUNTS.items():
        script = DIRECTORY + 'test-legacy-hmac-md5-' + name + '.py'
        result[('python3', script)] = dict(
            paths=[DRIVER, *HELPERS, 'assurance/' + FIXTURE + '/Cargo.toml',
                   'assurance/' + FIXTURE + '/Cargo.lock'],
            fixture=FIXTURE,
            compilers=('1.99.1',) if name in SINGLE_COMPILER else ('1.90.0', '1.99.1'),
            success={'contains': [f'\nRan {count} tests in '], 'unique_lines': ['OK']},
            establishes=f'Existing {count}-test HMAC-MD5 {name} compiler-checker regression suite. Original targets, panic modes and SIMD emission flags remain in the fingerprinted script. Cross-target emitted-code checks are not native execution or hosted/kernel/register-erasure qualification.')
    return result
