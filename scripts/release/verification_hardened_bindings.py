"""Existing hardened policy/acceptance commands, explicitly scoped and opt-in.

Legacy review and gate text is read by the source-policy commands themselves;
it affects those rows only. Neither these bindings nor status scans import or
execute a checker. No fresh native, sanitizer or proof claim is implied.
"""
import json
from pathlib import Path
from verification_assessment_bindings import ENV
from verification_cargo_bindings import BASE, fixture_inputs, source_inputs
from verification_miri_bindings import REJECT

DATA = Path(__file__).with_name('verification_hardened_inputs.json')
SHA2_TESTS = [
    'every_hardened_identity_matches_the_ordinary_algorithm',
    'padding_and_multiblock_boundaries_match_all_ordinary_states',
    'every_secret_output_transfers_and_executes_clearing_duty',
    'public_output_failure_is_unchanged_and_secret_failure_is_cleared',
    'canonical_bit_tail_matches_the_ordinary_bit_api',
    'every_partial_bit_width_matches_every_ordinary_identity',
    'sealed_capability_accepts_all_six_registered_types',
    'recoverable_unwind_clears_typed_secret_destination',
]
SHA3_TESTS = [
    'every_fixed_identity_matches_the_ordinary_algorithm',
    'every_fixed_secret_output_transfers_and_clears',
    'every_rate_and_multiblock_boundary_matches',
    'fixed_output_failure_is_atomic_by_classification',
    'every_partial_bit_width_matches_every_fixed_identity',
    'both_xofs_match_across_irregular_absorb_and_squeeze_boundaries',
    'xof_secret_fragments_transfer_and_clear_independently',
    'zero_length_secret_xof_output_is_a_valid_empty_owner',
    'bit_input_and_bit_output_match_both_ordinary_xofs',
    'every_partial_secret_xof_width_matches_and_clears',
    'sealed_capabilities_accept_only_registered_public_types',
    'cancel_and_early_drop_cover_absorber_and_reader_lifecycles',
    'recoverable_unwind_clears_typed_secret_destination',
]


def definitions():
    result = {
        ('python3', 'scripts/md5/test-md5-hardened.py'): ('md5', 'source', [
            'MD5 opaque identity rejects ten wrapper/ordinary/ambiguous substitutions',
            'Hardened MD5 policy: 152 boundary removals rejected; enforced ASan/LSan fatal exits PASS']),
        ('python3', 'scripts/sha1/test-sha1-hardened.py'): ('sha1', 'source', [
            'Opaque SHA-1 identity: two valid layouts; twelve regressions rejected',
            'Hardened SHA-1: 85 structural and 168 source-binding regressions rejected']),
        ('python3', 'scripts/sha2/test-sha2-hardened.py'): ('sha2', 'mutants', [
            'named SHA-2 finalizers reject twelve compiled arithmetic/cleanup mutations',
            'hardened SHA-2 policy rejects thirty-three cleanup, capability, borrowed-transfer, API, arithmetic, target/model and codegen regressions']),
    }
    for family, title in [('sha2', 'SHA-2'), ('sha3', 'FIPS 202')]:
        result[('python3', f'scripts/{family}/check-{family}-hardened.py')] = (
            family, 'acceptance', [f'complete hardened six-identity {title} API: PASS'])
    return result


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    declared = json.loads(DATA.read_text())
    groups = {'hardened-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed hardened selector: ' + row['id'])
        family, mode, markers = known[argv]
        key = 'hardened-' + row['id']
        groups[key] = {'paths': sorted(set([argv[1], *declared[family]['paths']]))}
        inputs = ['hardened-python', key]
        environment = dict(ENV)
        success = {'contains': markers, 'unique_lines': list(markers)}
        if mode != 'source':
            programs = ('cargo', 'rustc', 'rustdoc') if mode == 'acceptance' else ('cargo', 'rustc')
            groups[key]['tools'] = [{'program': p, 'toolchain': '1.99.1'} for p in programs]
            groups[key]['toml'] = {'Cargo.toml': ['workspace.package.edition', 'workspace.package.rust-version',
                'workspace.lints', 'workspace.resolver', 'profile.dev', 'profile.test', 'profile.release']}
            environment['RUSTUP_TOOLCHAIN'] = '1.99.1'
            inputs += source_inputs(groups, key + '-source', BASE | {'brynja-hash-' + family}, 'Cargo.lock')
        if mode == 'acceptance':
            inputs += fixture_inputs(groups, family + '-hardened-api', key + '-consumer')
            names = list(SHA2_TESTS if family == 'sha2' else SHA3_TESTS)
            names += ['tests::downstream_hardened_apis_are_usable']
            if family == 'sha2':
                names += ['hardened::tests::checked_length_' + n for n in
                          ('sha224', 'sha256', 'sha384', 'sha512', 'sha512_224', 'sha512_256')]
            success['unique_lines'] += ['test ' + n + ' ... ok' for n in names]
            success.update(minimum_tests=len(names), exact_tests=len(names))
        establishes = {
            'source': 'Existing source-policy mutations and synthetic emitted-artifact checks; '
                      'MD5 sanitizer subprocesses are mocked. No compiler, native, ASan or proof execution.',
            'mutants': 'Existing SHA-2 source-policy mutations plus twelve compiled finalizer arithmetic/cleanup '
                       'mutations with positive controls in debug/release; no native backend qualification.',
            'acceptance': 'Existing hardened API/runtime tests and downstream consumer, plus thumbv7em-none-eabi '
                          'compile check. Cross-compilation is not execution on bare-metal hardware.',
        }[mode]
        check = dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=inputs, environment=environment, reject_environment=REJECT,
            success=success, timeout_seconds={'source': 300, 'mutants': 3000, 'acceptance': 1200}[mode],
            log_bytes=16777216, establishes=establishes + ' Legacy policy review/gate text affects only this row.')
        if mode != 'source':
            check['platform'] = 'linux-x86_64'
        checks.append(check)
    return dict(schema=1, groups=groups, checks=checks)
