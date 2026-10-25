"""Compile real private legacy-engine defects; do not edit repository sources."""
from pathlib import Path
import shutil
import tomllib


class NormalizationCompiledTests:
    def test_compiled_scalar_constructor_provenance(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'normalization-mutants'
        workspace = tomllib.loads((d.ROOT / 'Cargo.toml').read_text())['workspace']
        paths = {name: work / name for name in ('brynja-legacy-hmac', 'brynja-legacy-hmac-std')}
        for name, path in paths.items():
            source = d.ROOT / 'crates' / name
            shutil.copytree(source / 'src', path / 'src')
            shutil.copyfile(source / 'README.md', path / 'README.md')
            manifest = (source / 'Cargo.toml').read_text()
            for field in ('edition', 'rust-version', 'license', 'repository'):
                manifest = manifest.replace(field + '.workspace = true', field + ' = "' + workspace['package'][field] + '"')
            for dependency in ('brynja-core', 'brynja-crypto-cpu-std', 'brynja-legacy-sha1', 'brynja-legacy-md5'):
                location = str(d.ROOT / 'crates' / dependency)
                manifest = manifest.replace(dependency + '.workspace = true', dependency + ' = { path = "' + location + '" }')
                manifest = manifest.replace(dependency + ' = { workspace = true,', dependency + ' = { path = "' + location + '",')
            manifest = manifest.replace('path = "../brynja-legacy-hmac"', 'path = "' + str(paths['brynja-legacy-hmac']) + '"')
            manifest = manifest.replace('path = "../', 'path = "' + str(d.ROOT / 'crates') + '/')
            (path / 'Cargo.toml').write_text(manifest.replace('[lints]\nworkspace = true', '') + '\n[workspace]\n')
        fixture = work / 'fixture'
        shutil.copytree(d.FIXTURE.parent / 'src', fixture / 'src')
        shutil.copyfile(d.FIXTURE.parent / 'Cargo.lock', fixture / 'Cargo.lock')
        manifest = d.FIXTURE.read_text().replace('../../crates/brynja-legacy-hmac-std', str(paths['brynja-legacy-hmac-std']))
        manifest = manifest.replace('"../../crates/brynja-legacy-hmac"', '"' + str(paths['brynja-legacy-hmac']) + '"')
        (fixture / 'Cargo.toml').write_text(manifest.replace('../../crates/', str(d.ROOT / 'crates') + '/'))
        engine = paths['brynja-legacy-hmac'] / 'src/engine.rs'
        original = engine.read_text()
        mutants = (
            ('key.len() > 64', 'key.len() > 63'),
            ('key.len() > 64', 'key.len() > 65'),
            ('!key.is_empty()', 'key.is_empty()'),
            ('pad.prefix(bytes.len())?, bytes', 'pad.prefix(bytes.len())?, &key[..bytes.len()]'),
            ('pad.prefix(bytes.len())?, bytes', 'pad.prefix(bytes.len() - 1)?, &bytes[..bytes.len() - 1]'),
            ('copy_secret_region(pad.prefix(bytes.len())?, bytes).map_err(Error::from)',
             'let _ = copy_secret_region(pad.prefix(bytes.len())?, bytes); Ok(())'),
        )
        count = 0
        for target in (d.TARGETS[0], d.TARGETS[2]):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True, fixture / 'Cargo.toml',
                              paths['brynja-legacy-hmac-std'] / 'Cargo.toml', paths['brynja-legacy-hmac'] / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            for before, after in mutants:
                self.assertIn(before, original)
                try:
                    engine.write_text(original.replace(before, after, 1))
                    artifacts = emit()  # An uncompilable mutant is a test failure.
                    with self.subTest(target=target, mutation=before), self.assertRaisesRegex(
                            ValueError, 'normalization|scalar short-key pad copy provenance/population'):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    engine.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 12)
        print('Legacy scalar normalization: 12 compiled constructor defects rejected', flush=True)
