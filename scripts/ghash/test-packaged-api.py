"""Fail-closed controls for the portable GHASH archive consumer."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('acceptance', Path(__file__).with_name('check-packaged-api.py'))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


class ArchiveControls(unittest.TestCase):
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

    def graph(self):
        api.check_graph({'packages': self.packages, 'resolve': {'nodes': list(self.nodes.values()),
                         'root': 'consumer'}}, self.consumer, self.archives, self.versions, 'brynja')

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
