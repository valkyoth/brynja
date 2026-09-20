#!/usr/bin/env python3
"""Regression tests for the development-only observation collector."""
import os
import unittest
from unittest.mock import patch

import check_callers as audit


def sample(matches=0, api_profile='movable'):
    algorithms = audit.THREADED_ALGORITHMS if api_profile == 'threaded' else audit.HIGHER_ALGORITHMS if api_profile in ('higher', 'accelerated') else audit.ALGORITHMS
    cases = 18 if api_profile == 'threaded' else 28
    return 'CALLER_API_PROFILE: ' + api_profile + '\n' + '\n'.join(f'CALLER_AUDIT: {name}; cases={cases}; input_marker_cases={matches}; '
                     'qualifies_cleanup=false' for name in sorted(algorithms)) + (
                         '\nCALLER_THREADS: kernel=X86Keccak; workers=2; block=8; profiles=portable,static,batch; coordinator_only=true\ntest result: ok. 6 passed; 0 failed; 0 ignored;\n'
                         if api_profile == 'threaded' else
                         '\nCALLER_ACCELERATION: kernel=X86Keccak; no_fallback=true\ntest result: ok. 6 passed; 0 failed; 0 ignored;\n'
                         if api_profile == 'accelerated' else '\ntest result: ok. 5 passed; 0 failed; 0 ignored;\n')


class ObservationTests(unittest.TestCase):
    def test_accelerated_dependency_features_use_own_workspace_manifest(self):
        common = ['--offline', '--manifest-path', str(audit.FIXTURE / 'Cargo.toml')]
        for package in audit.ACCELERATED_PACKAGES:
            command = audit.emitted_command('1.90.0', common, package, 'accelerated')
            self.assertEqual(command[command.index('--manifest-path') + 1], str(audit.ROOT / 'Cargo.toml'))
        command = audit.emitted_command('1.90.0', common, 'brynja-caller-residue-audit', 'accelerated')
        self.assertEqual(command[command.index('--manifest-path') + 1], str(audit.FIXTURE / 'Cargo.toml'))
        self.assertEqual(common[-1], str(audit.FIXTURE / 'Cargo.toml'))

    def test_scoped_feature_applies_only_to_fixture_not_dependency_packages(self):
        for profile in audit.PROFILES[:-1]:
            for package in (*audit.PACKAGES, *audit.HIGHER_PACKAGES, 'brynja-crypto-cpu', 'brynja-caller-residue-audit'):
                command = audit.emitted_command('1.90.0', ['--offline'], package, profile)
                self.assertEqual(command[:4], ['cargo', '+1.90.0', 'rustc', '--offline'])
                self.assertEqual(command[4:6], ['-p', package])
                features = ['--features', profile] if profile != 'movable' and package == 'brynja-caller-residue-audit' else []
                if profile == 'accelerated' and package in audit.ACCELERATED_PACKAGES:
                    features = ['--features', 'hardened-execution']
                self.assertEqual(command[6:], [*features, '--lib', '--', '--emit=mir,llvm-ir,asm'])

    def test_threaded_profile_binds_coordinator_only_and_all_routes(self):
        log = sample(api_profile='threaded')
        self.assertEqual(set(audit.observations(log, 'threaded', 'X86Keccak')), audit.THREADED_ALGORITHMS)
        for before, after in (('coordinator_only=true', 'coordinator_only=false'), ('workers=2', 'workers=1'),
                              ('static,batch', 'static'), ('kernel=X86Keccak', 'kernel=ArmKeccak'),
                              ('cases=18', 'cases=28'), ('6 passed', '5 passed'), ('CALLER_AUDIT: batch128', 'MISSING: batch128')):
            with self.assertRaises(ValueError):
                audit.observations(log.replace(before, after), 'threaded', 'X86Keccak')
        with self.assertRaises(ValueError):
            audit.observations(log, 'accelerated', 'X86Keccak')
        command = audit.emitted_threaded_tree('1.90.0', ['--locked', '--offline'])
        self.assertEqual(command, ['cargo', '+1.90.0', 'build', '--locked', '--offline', '--features', 'threaded', '--lib'])

    def test_accelerated_route_requires_exact_target_and_revocation_control(self):
        log = sample(api_profile='accelerated')
        self.assertEqual(set(audit.observations(log, 'accelerated', 'X86Keccak')), audit.HIGHER_ALGORITHMS)
        for changed in (log.replace('X86Keccak', 'ArmKeccak'), log.replace('no_fallback=true', 'no_fallback=false'),
                        log.replace('6 passed', '5 passed'), log + '\nCALLER_ACCELERATION: kernel=X86Keccak; no_fallback=true',
                        log.replace('CALLER_ACCELERATION:', 'UNRECORDED:'),
                        log.replace('CALLER_API_PROFILE: accelerated', 'CALLER_API_PROFILE: higher')):
            with self.assertRaises(ValueError):
                audit.observations(changed, 'accelerated', 'X86Keccak')
        for kernel in (None, 'Portable', 'ArmKeccak'):
            with self.assertRaises(ValueError):
                audit.observations(log, 'accelerated', kernel)

    def test_avx2_requires_flags_on_every_exposed_processor(self):
        good = 'processor : 0\nflags : avx avx2 xsave\n\nprocessor : 1\nflags : avx avx2 xsave\n'
        audit.require_native_avx2(good)
        for text in ('', good.replace('avx2', 'avx512f', 1), good.replace('xsave', '', 1),
                     good.replace('flags :', 'missing :', 1), good.replace('avx ', '', 1)):
            with self.assertRaises(ValueError):
                audit.require_native_avx2(text)

    def test_higher_requires_all_twelve_identities_and_matching_profile(self):
        self.assertEqual(set(audit.observations(sample(api_profile='higher'), 'higher')), audit.HIGHER_ALGORITHMS)
        for name in audit.HIGHER_ALGORITHMS:
            for log in (sample(api_profile='higher').replace('CALLER_AUDIT: '+name+';', 'OMITTED: '+name+';'),
                        sample(api_profile='higher').replace('CALLER_AUDIT: '+name+';', 'CALLER_AUDIT: unknown;')):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    audit.observations(log, 'higher')
        for profile in ('movable', 'scoped'):
            with self.assertRaises(ValueError):
                audit.observations(sample(api_profile='higher'), profile)
        with self.assertRaises(ValueError):
            audit.emitted_command('1.90.0', [], 'brynja-caller-residue-audit', 'unknown')

    def test_profile_is_explicit_and_cannot_be_substituted(self):
        self.assertEqual(set(audit.observations(sample(api_profile='scoped'), 'scoped')), audit.ALGORITHMS)
        for log, profile in ((sample(), 'scoped'), (sample(api_profile='scoped'), 'movable'),
                             (sample().replace('CALLER_API_PROFILE: movable\n', ''), 'movable'),
                             (sample() + '\nCALLER_API_PROFILE: movable', 'movable'),
                             (sample(api_profile='unknown'), 'unknown')):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                audit.observations(log, profile)

    def test_residue_is_recorded_not_misreported_as_a_clean_verdict(self):
        rows = audit.observations(sample(28))
        self.assertEqual(set(rows), audit.ALGORITHMS)
        self.assertTrue(all(row['input_marker_cases'] == 28 for row in rows.values()))

    def test_zero_matches_are_only_observations(self):
        rows = audit.observations(sample())
        self.assertTrue(all(set(row) == {'cases', 'input_marker_cases'} for row in rows.values()))

    def test_missing_duplicate_or_wrong_algorithm_rejected(self):
        for log in (sample().replace('CALLER_AUDIT: md5', 'unrecorded: md5'),
                    sample() + sample(), sample().replace('md5', 'unknown')):
            with self.subTest(log=log), self.assertRaises(ValueError):
                audit.observations(log)

    def test_missing_qualification_disclaimer_rejected(self):
        with self.assertRaises(ValueError):
            audit.observations(sample().replace('qualifies_cleanup=false', 'qualifies_cleanup=true'))

    def test_missing_or_skipped_controls_rejected(self):
        for result in ('', 'test result: ok. 4 passed; 0 failed; 1 ignored;',
                       'test result: FAILED. 4 passed; 1 failed; 0 ignored;'):
            with self.subTest(result=result), self.assertRaises(ValueError):
                audit.observations(sample().replace(
                    'test result: ok. 5 passed; 0 failed; 0 ignored;', result))

    def test_invalid_counts_rejected(self):
        for log in (sample().replace('cases=28', 'cases=27'), sample(29), sample(-1)):
            with self.subTest(log=log), self.assertRaises(ValueError):
                audit.observations(log)

    def test_build_overrides_removed_without_repurposing_system_paths(self):
        poisoned = dict.fromkeys(('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
                                  'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC',
                                  'CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET',
                                  'CARGO_PROFILE_RELEASE_LTO',
                                  'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'), 'hostile')
        with patch.dict(os.environ, {'PATH': '/test/bin', 'HOME': '/test/home', **poisoned}, clear=True):
            self.assertEqual(audit.clean_environment(), {'PATH': '/test/bin', 'HOME': '/test/home'})


if __name__ == '__main__':
    unittest.main()
