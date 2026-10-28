"""Historical classification never expands current release reuse."""
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest

import historical_command_scope as scope
import verification_carry_forward as carry
import verification_plan as plans


class HistoricalCommandScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='brynja-historical-scope-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / scope.PATH
        self.path.parent.mkdir(parents=True)
        self.old = subprocess.check_output(['git', 'show',
            '4ae6cfb207209adef7de8b7877c87fbbcc85c0e7:' + scope.PATH], cwd=plans.ROOT)
        self.path.write_bytes(self.old)

    def entry(self, driver):
        command = 'python3 ' + driver
        return {'command': command, 'argv': command.split(), 'phase': 'repository',
                'stdin': None, 'environment': {}}

    def context(self, entry):
        return {'plan': {'groups': ['legacy_hmac'], 'full_phases': [],
                         'verifiers': {}, 'evidence': {'changed_paths': []}},
                'manifest': {'commands': [entry]}, 'public_checkpoint': False}

    def test_only_two_exact_historical_commands_get_old_ownership(self):
        for driver in scope.DRIVERS:
            command = 'python3 ' + driver
            self.assertEqual(scope.owners(command, self.root, {'hmac', 'legacy_hmac'}), {'hmac'})
            for unknown in (command + ' --new-mode', 'python3 scripts/hmac/other.py',
                            'python3 scripts/legacy-hmac/check-legacy-hmac.py'):
                self.assertEqual(scope.owners(unknown, self.root, {'hmac', 'legacy_hmac'}),
                                 {'hmac', 'legacy_hmac'})

    def test_current_candidate_still_requires_both_families(self):
        for driver in scope.DRIVERS:
            entry = self.entry(driver)
            context = self.context(entry)
            self.assertTrue(carry.disposition(entry, context).startswith('run:'))
            context['historical_ownership_root'] = self.root
            self.assertTrue(carry.disposition(entry, context).startswith('reuse:'))

    def test_raw_classifier_drift_or_unknown_scope_does_not_exempt(self):
        command = 'python3 scripts/hmac/test-hmac-package.py'
        for raw in (self.old + b'\n', self.old.replace(b'\n', b'\r\n'),
                    (plans.ROOT / scope.PATH).read_bytes()):
            self.path.write_bytes(raw)
            self.assertEqual(scope.owners(command, self.root, {'hmac', 'legacy_hmac'}),
                             {'hmac', 'legacy_hmac'})
        self.path.write_bytes(self.old)
        self.assertEqual(scope.owners(command, self.root, {'hmac', 'legacy_hmac', 'core'}),
                         {'hmac', 'legacy_hmac', 'core'})

    def test_missing_and_symlinked_classifier_fail_closed(self):
        command = 'python3 scripts/hmac/test-hmac-package.py'
        self.path.unlink()
        with self.assertRaises(OSError):
            scope.owners(command, self.root, {'hmac', 'legacy_hmac'})
        self.path.symlink_to(plans.ROOT / scope.PATH)
        with self.assertRaises(ValueError):
            scope.owners(command, self.root, {'hmac', 'legacy_hmac'})

    def test_historical_rule_never_waives_public_or_changed_command_or_hmac(self):
        entry = self.entry('scripts/hmac/test-hmac-package.py')
        original = self.context(entry)
        original['historical_ownership_root'] = self.root
        for case in ('public', 'driver', 'hmac', 'full', 'missing'):
            context = copy.deepcopy(original)
            if case == 'public': context['public_checkpoint'] = True
            if case == 'driver': context['plan']['evidence']['changed_paths'] = [entry['argv'][1]]
            if case == 'hmac': context['plan']['groups'] = ['hmac']
            if case == 'full': context['plan']['full_phases'] = ['repository']
            if case == 'missing': context['manifest']['commands'] = []
            with self.subTest(case=case):
                self.assertTrue(carry.disposition(entry, context).startswith('run:'))
