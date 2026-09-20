#!/usr/bin/env python3
"""Regression tests for the development-only observation collector."""
import os
import unittest
from unittest.mock import patch

import check_callers as audit


def sample(matches=0, api_profile='movable'):
    algorithms = audit.HIGHER_ALGORITHMS if api_profile == 'higher' else audit.ALGORITHMS
    return 'CALLER_API_PROFILE: ' + api_profile + '\n' + '\n'.join(f'CALLER_AUDIT: {name}; cases=28; input_marker_cases={matches}; '
                     'qualifies_cleanup=false' for name in sorted(algorithms)) + (
                         '\ntest result: ok. 5 passed; 0 failed; 0 ignored;\n')


class ObservationTests(unittest.TestCase):
    def test_scoped_feature_applies_only_to_fixture_not_dependency_packages(self):
        for profile in ('movable', 'scoped', 'higher'):
            for package in (*audit.PACKAGES, *audit.HIGHER_PACKAGES, 'brynja-caller-residue-audit'):
                command = audit.emitted_command('1.90.0', ['--offline'], package, profile)
                self.assertEqual(command[:4], ['cargo', '+1.90.0', 'rustc', '--offline'])
                self.assertEqual(command[4:6], ['-p', package])
                features = ['--features', profile] if profile != 'movable' and package == 'brynja-caller-residue-audit' else []
                self.assertEqual(command[6:], [*features, '--lib', '--', '--emit=mir,llvm-ir,asm'])

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
