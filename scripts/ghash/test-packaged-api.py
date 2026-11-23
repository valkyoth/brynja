"""Fail-closed controls for the portable GHASH archive consumer."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('acceptance', Path(__file__).with_name('check-packaged-api.py'))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


class ArchiveControls(unittest.TestCase):
    def test_exactly_one_unfiltered_suite_at_declared_count(self):
        for n in (1, 3, 4):
            line = f'test result: ok. {n} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s'
            self.assertTrue(api.exact_suite('other output\n' + line + '\n', n))
            for bad in ('', 'extra ' + line, line + '\n' + line, line.replace(f'{n} passed', f'1{n} passed'),
                        line.replace('0 filtered', '1 filtered'), line.replace('0 ignored', '1 ignored')):
                self.assertFalse(api.exact_suite(bad, n))

    def test_invalid_cargo_environment_blocks_expected_failure_probe(self):
        # Run check() through both negative-probe paths. Stub only successful
        # Cargo calls; deny the environment at the selected negative probe.
        def positive(cmd, cwd, env):
            count = 1 if '--doc' in cmd else 4 if 'ghash_lifecycle' in cmd else 3
            summary = f'test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0s'
            return SimpleNamespace(stdout='{}' if 'metadata' in cmd else summary)

        (self.consumer / 'src').mkdir(parents=True)
        for permitted in (0, 3):  # feature gate; first ownership probe
            with self.subTest(permitted=permitted), patch.object(api.pkg, 'run', positive), \
                 patch.object(api, 'check_graph'), patch.object(api.pkg, 'diagnostic_matches', return_value=True), \
                 patch.object(api.pkg.cargo_environment, 'check',
                              side_effect=[None] * permitted + [ValueError('unsafe config')]) as guard, \
                 patch.object(api.pkg.subprocess, 'run') as launch:
                with self.assertRaisesRegex(ValueError, 'unsafe config'):
                    api.check(self.consumer, '1.90.0', 'brynja', self.versions, {})
                guard.assert_called_with(self.consumer, {})
                self.assertEqual(launch.call_count, permitted)

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.archives = self.root / 'unpacked'
        self.consumer = self.root / 'consumer'
        self.versions = {name: '1' for name in ('brynja', 'brynja-core', 'brynja-crypto')}
        self.packages = [{'id': name, 'name': name, 'features': {'default': []},
                          'manifest_path': str(self.archives / (name + '-1') / 'Cargo.toml')}
                         for name in self.versions]
        self.packages.append(dict(name='ghash-consumer', id='consumer',
                                  manifest_path=str(self.consumer / 'Cargo.toml')))
        self.nodes = {p['id']: dict(id=p['id'], features=[], deps=[]) for p in self.packages}
        self.nodes['consumer']['deps'] = [dict(name='subject', pkg='brynja')]
        self.nodes['brynja']['features'] = ['hazmat-ghash']
        self.nodes['brynja-crypto']['features'] = ['default', 'hazmat-ghash']

    def graph(self, candidate=False):
        api.check_graph({'packages': self.packages, 'resolve': {'nodes': list(self.nodes.values()),
                         'root': 'consumer'}}, self.consumer, self.archives, self.versions, 'brynja',
                        candidate=candidate)

    def test_candidate_requires_cpu_edge_and_only_reviewed_archive_features(self):
        cpu = 'brynja-crypto-cpu'
        self.versions[cpu] = '1'
        self.packages.append(dict(id=cpu, name=cpu, features={'default': []},
                                  manifest_path=str(self.archives / (cpu + '-1') / 'Cargo.toml')))
        self.nodes[cpu] = dict(id=cpu, features=[], deps=[])
        for name in ('brynja', 'brynja-crypto'):
            self.nodes[name]['features'].append('cpu')
        with self.assertRaisesRegex(ValueError, 'dependency edge'):
            self.graph(candidate=True)
        self.nodes['brynja-crypto']['deps'].append(dict(name='brynja_crypto_cpu', pkg=cpu))
        self.graph(candidate=True)
        with self.assertRaisesRegex(ValueError, 'opt-in'):
            self.graph()
        self.nodes[cpu]['features'].append('aes-runtime-execution')
        with self.assertRaisesRegex(ValueError, 'transitive'):
            self.graph(candidate=True)
        self.nodes[cpu]['features'].clear()
        self.packages[-1]['manifest_path'] = str(api.ROOT / 'crates' / cpu / 'Cargo.toml')
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.graph(candidate=True)

    def test_accepts_archive_graph_and_rejects_checkout_fallback(self):
        self.graph()
        self.packages[0]['manifest_path'] = str(api.ROOT / 'crates/brynja/Cargo.toml')
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.graph()

    def test_rejects_unexpected_feature_and_changed_defaults(self):
        for name in ('brynja', 'brynja-crypto', 'brynja-core'):
            self.nodes[name]['features'].append('cpu')
            with self.assertRaisesRegex(ValueError, 'opt-in|transitive'):
                self.graph()
            self.nodes[name]['features'].pop()
        self.packages[2]['features']['default'].append('cpu')
        with self.assertRaisesRegex(ValueError, 'nonempty'):
            self.graph()

    def test_requires_actual_facade_entry(self):
        self.nodes['consumer']['deps'][0]['pkg'] = 'brynja-crypto'
        with self.assertRaisesRegex(ValueError, 'entry point'):
            self.graph()

    def test_changed_archived_vectors_do_not_become_expected_results(self):
        dest = self.archives / 'brynja-crypto-1/tests/ghash_vectors/nist.rs'
        dest.parent.mkdir(parents=True)
        dest.write_text('// fixture replaced')
        with self.assertRaisesRegex(ValueError, 'frozen public test changed'):
            api.prepare(self.root, 'brynja', self.versions)


if __name__ == '__main__':
    unittest.main()
