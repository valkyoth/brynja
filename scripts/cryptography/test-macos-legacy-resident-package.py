#!/usr/bin/env python3
"""Cheap legacy resident corpus, archive, dependency and unsupported-host tests."""
import copy
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import macos_legacy_resident_oracle as oracle

spec = importlib.util.spec_from_file_location('legacy_package',
    Path(__file__).with_name('check-macos-legacy-resident-package.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class LegacyPackageTests(unittest.TestCase):
    def test_oracle_population_canonical_bits_and_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'src').mkdir()
            with patch('subprocess.run', side_effect=AssertionError('unexpected subprocess')):
                self.assertEqual(oracle.write_consumer(root), 169)
            rows = (root/'src/legacy.txt').read_text().splitlines()
            self.assertEqual(sum(int(row.split()[0]) >= 512 for row in rows), 89)
            for row in rows:
                bits, data, sha1, md5 = row.split()
                bits = int(bits)
                raw = b'' if data == '-' else bytes.fromhex(data)
                self.assertEqual(len(raw), (bits+7)//8)
                if bits % 8:
                    self.assertEqual(raw[-1] & ((1 << (8-bits%8))-1), 0)
                self.assertEqual((len(sha1), len(md5)), (40, 32))
            for token in ('s::Session::new', 's::CompiledSession::new', 'm::Session::new',
                          'm::batch::Session::new', 'Aarch64Sha1', 'Aarch64Neon', 'vector_blocks>0'):
                self.assertIn(token, oracle.SOURCE)

    def test_wrong_host_never_runs_package_or_instruction(self):
        with patch('subprocess.check_output', return_value='host: x86_64-unknown-linux-gnu\n'):
            with patch('subprocess.run', side_effect=AssertionError('unexpected subprocess')):
                with self.assertRaisesRegex(ValueError, 'requires native Apple Silicon'):
                    package.execute('1.99.1', Path('/unused'))

    def test_graph_requires_private_legacy_closure_and_real_package_paths(self):
        consumer = Path('/fixture/consumer')
        names = ('brynja-core', 'brynja-hash-core', 'brynja-legacy-sha1', 'brynja-legacy-md5',
                 'brynja-legacy-sha1-std', 'brynja-legacy-md5-std')
        roots = {name: Path('/fixture/packages')/name for name in names}
        entries = [('resident-legacy-consumer', consumer), *roots.items()]
        metadata = {'packages': [dict(name=name, source=None, manifest_path=str(path/'Cargo.toml'))
                                 for name, path in entries]}
        package.validate_graph(metadata, consumer, roots)
        changes = []
        changed = copy.deepcopy(metadata)
        changed['packages'].append(dict(name='brynja-crypto-cpu-std', source=None, manifest_path='/bad'))
        changes.append(changed)
        for key, value in (('source', 'registry'), ('manifest_path', '/workspace/Cargo.toml')):
            changed = copy.deepcopy(metadata)
            changed['packages'][1][key] = value
            changes.append(changed)
        changed = copy.deepcopy(metadata)
        changed['packages'].pop()
        changes.append(changed)
        for changed in changes:
            with self.assertRaises(ValueError):
                package.validate_graph(changed, consumer, roots)

    def test_archive_rejects_escape_links_duplicates_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for names, kind, size in ((['pkg/file'], tarfile.REGTYPE, 1),
                                     (['../escape'], tarfile.REGTYPE, 1),
                                     (['/absolute'], tarfile.REGTYPE, 1),
                                     (['other/file'], tarfile.REGTYPE, 1),
                                     (['pkg/link'], tarfile.SYMTYPE, 0),
                                     (['pkg/file']*2, tarfile.REGTYPE, 1),
                                     (['pkg/huge'], tarfile.REGTYPE, 16*1024*1024+1)):
                archive = root/'fixture.tar'
                with tarfile.open(archive, 'w') as bundle:
                    for name in names:
                        entry = tarfile.TarInfo(name)
                        entry.type, entry.size = kind, size
                        bundle.addfile(entry, io.BytesIO(b'x'*size))
                if names == ['pkg/file']:
                    package.extract(archive, root/'out', 'pkg')
                    self.assertEqual((root/'out/pkg/file').read_bytes(), b'x')
                else:
                    with self.assertRaises(ValueError):
                        package.extract(archive, root/'out', 'pkg')


if __name__ == '__main__':
    unittest.main()
