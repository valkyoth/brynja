"""Old execution populations are not expanded by new candidate families."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import detached_catalog as catalog
import detached_job as jobs
import historical_groups as groups
import verification_plan as plans


class HistoricalGroupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.write('scripts/zeroization/miri_scope.py', "GROUPS = ('core', 'sha2')\n")
        self.write('scripts/zeroization/check-zeroization-miri.sh', 'all_groups=(core sha2)\n')
        self.write('scripts/checks.sh', '# BEGIN VERIFICATION CATALOG\ncargo test --workspace\n')
        self.write('scripts/zeroization/check-zeroization-sanitizer.sh', 'cargo test --workspace\n')
        self.write('scripts/ci/check-rust-version-matrix.sh',
                   'toolchains=(1.99.1)\n# BEGIN MATRIX CATALOG\ncargo check --workspace\ndone\n')
        self.current = {'schema': 1, 'fingerprint': 'a' * 64, 'approval_required': True,
                        'stage': 'internal', 'base': 'v0.24.54', 'head': 'b' * 40,
                        'full_phases': list(catalog.PHASES), 'groups': list(plans.scope.GROUPS),
                        'verifiers': {p: list(plans.scope.GROUPS) for p in ('asan', 'miri', 'kani')}}
        self.old = groups.project(self.current, ('core', 'sha2'))

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def entries(self):
        return catalog.selected(self.old, ['kani'], 'a' * 64, root=self.root, historical=True)

    def manifest(self):
        return {'schema': 2, 'sources': {'sealed': True}, 'plan': self.old,
                'phases': ['kani'], 'approval': 'a' * 64, 'shards': 1,
                'miri_profile': 'routine', 'commands': self.entries()}

    def test_literal_inventory_is_data_and_matches_shell(self):
        self.assertEqual(groups.inventory(self.root), ('core', 'sha2'))
        for value in ("GROUPS = __import__('sys').exit(99)\n", "GROUPS = ('core', 'core')\n",
                      "GROUPS = ('future_unknown',)\n", "GROUPS = ()\n",
                      "GROUPS = ('sha2', 'core')\n", "GROUPS = ('core',)\nGROUPS = ('sha2',)\n",
                      "GROUPS = OTHER = ('core', 'sha2')\n", "GROUPS = ['core', 'sha2']\n"):
            with self.subTest(value=value):
                self.write('scripts/zeroization/miri_scope.py', value)
                with self.assertRaises((ValueError, TypeError)):
                    groups.inventory(self.root)

    def test_source_inventory_cannot_be_symlinked_or_oversized(self):
        path = self.root / 'scripts/zeroization/miri_scope.py'
        path.rename(path.with_suffix('.saved'))
        path.symlink_to(path.with_suffix('.saved'))
        with self.assertRaisesRegex(ValueError, 'symlink'):
            groups.inventory(self.root)
        path.unlink()
        path.write_bytes(b' ' * (1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, 'oversized'):
            groups.inventory(self.root)

    def test_old_kani_catalog_does_not_claim_hmac(self):
        entries = self.entries()
        self.assertEqual([e['command'] for e in entries],
                         ['scripts/assurance/check-kani.sh --required-groups core sha2'])
        self.assertIn('hmac', self.current['groups'])
        # Candidate catalog still requires today's mandatory baseline.
        with self.assertRaisesRegex(ValueError, 'mandatory current repository check'):
            catalog.selected(self.current, ['kani'], 'a' * 64, root=self.root)

    def test_historical_reconstruction_preserves_all_other_identity_checks(self):
        manifest = self.manifest()
        with patch.object(jobs.records, 'sources', return_value=manifest['sources']), \
             patch.object(jobs.plans, 'build', return_value=self.current):
            jobs.validate_source(manifest, self.root, historical=True)
            # Live jobs may not silently inherit the historical projection.
            with self.assertRaisesRegex(ValueError, 'plan or approval changed'):
                jobs.validate_source(manifest, self.root)
            for change in ('fingerprint', 'groups', 'commands', 'approval', 'sources'):
                altered = copy.deepcopy(manifest)
                if change == 'fingerprint':
                    altered['plan']['fingerprint'] = '0' * 64
                elif change == 'groups':
                    altered['plan']['groups'].append('hmac')
                elif change == 'commands':
                    altered['commands'] = []
                elif change == 'approval':
                    altered['approval'] = '0' * 64
                else:
                    altered['sources'] = {}
                with self.subTest(change=change), self.assertRaises(ValueError):
                    jobs.validate_source(altered, self.root, historical=True)

    def test_current_hmac_work_is_not_covered_by_old_commands(self):
        import verification_carry_forward as carry
        current = {'phase': 'kani', 'argv': ['python3', 'scripts/hmac/check-hmac-kani.py'],
                   'command': 'python3 scripts/hmac/check-hmac-kani.py',
                   'environment': {}, 'stdin': None}
        self.assertFalse(carry.covered(current, self.entries()))
