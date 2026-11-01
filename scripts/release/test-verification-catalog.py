#!/usr/bin/env python3
"""Fake historical files and discovery-only reconciliation; no crypto execution."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import verification_catalog_export as catalog


class CatalogTests(unittest.TestCase):
    def test_discovery_cannot_spawn_a_verifier_or_contact_a_service(self):
        with patch('subprocess.Popen', side_effect=AssertionError('discovery executed a process')):
            rows = catalog.definitions()
        self.assertEqual(len({r['id'] for r in rows}), len(rows))
        phases = {r['phase'] for r in rows}
        self.assertTrue({'miri', 'kani', 'asan', 'matrix', 'repository', 'entrypoint', 'workflow'} <= phases)
        profiles = {r['definition'].get('profile') for r in rows if r['phase'] == 'miri'}
        self.assertEqual(profiles, {'routine', 'extended', 'existing-full'})
        self.assertTrue(all(not r['history'] and r['reason'] for r in rows))
        shared = [r for r in rows if r['phase'] == 'entrypoint' and r['label'].startswith('scripts/cryptography/')]
        self.assertTrue(shared)
        self.assertTrue(all(r['families'] == ['shared-cryptography'] for r in shared))

    def test_import_preserves_failure_time_and_does_not_invent_reuse_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = []
            observations = []
            for result, time in [('passed', '2026-01-01T01:00:00Z'), ('failed', '2026-01-02T01:00:00Z'), ('reused', '2026-01-03T01:00:00Z')]:
                observations.append(dict(id='miri-old', families=['md5'], phase='miri', label='old exact task',
                    state=result, ended=time, commit='IMPORT_CAMPAIGN', receipt='receipt', log_sha256='log'))
            raw = json.dumps(dict(schema=1, release_authorized=False, observations=observations)).encode()
            (root / 'old.json').write_bytes(raw)
            index = {'files':[{'path':'old.json', 'sha256':hashlib.sha256(raw).hexdigest()}]}
            counts = catalog.history(rows, index, root)
            self.assertEqual(counts['original_rows'], 3)
            self.assertEqual(rows[0]['phase'], 'retired-history')
            self.assertEqual([r['result'] for r in rows[0]['history']], ['passed', 'failed', 'reused'])
            self.assertEqual(rows[0]['history'][1]['ended'], observations[1]['ended'])
            self.assertIn('unresolved original execution', rows[0]['history'][2]['source'])
            self.assertNotIn('current pass', catalog.markdown({'entries':rows}).split('## Every catalog assessment')[1])
            (root / 'old.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'digest changed'):
                catalog.history([], index, root)

    def test_timestamps_require_an_explicit_zone(self):
        with self.assertRaises(ValueError):
            catalog.time_key('2026-01-01T01:00:00')


if __name__ == '__main__':
    unittest.main()
