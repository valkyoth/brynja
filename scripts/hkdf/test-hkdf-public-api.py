#!/usr/bin/env python3
"""Fail-closed controls for the packaged public HKDF consumer runner."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'public_api', Path(__file__).with_name('check-hkdf-public-api.py'))
api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api)


def diagnostic(code='E0308', filename='src/bin/probe.rs', primary=True):
    return {'reason': 'compiler-message', 'message': {
        'level': 'error', 'code': {'code': code},
        'spans': [{'is_primary': primary, 'file_name': filename}]}}


def result(*records, status=1):
    return subprocess.CompletedProcess([], status, '\n'.join(map(json.dumps, records)), '')


class PublicApiTests(unittest.TestCase):
    def test_packaged_graph_rejects_checkout_fallback_and_legacy(self):
        root = Path('/tmp/hkdf-public-api-test/unpacked')
        packages = [{'name': name, 'manifest_path': str(root / name / 'Cargo.toml')}
                    for name in ('hkdf-packaged-consumer', 'brynja', 'brynja-core')]
        api.packaged_graph({'packages': packages}, root, 'modern')
        for changed in ([], packages[:-1],
                        packages + [{'name': 'brynja-crypto', 'manifest_path': '/checkout/Cargo.toml'}],
                        packages + [{'name': 'brynja-legacy-hkdf',
                                     'manifest_path': str(root / 'legacy/Cargo.toml')}]):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                api.packaged_graph({'packages': changed}, root, 'modern')

    def test_registration_tracks_packages_fixtures_tools_and_signals(self):
        registry = tomllib.loads((api.ROOT / 'verification/checks.toml').read_text())
        for family, component in (('modern', 'hkdf'), ('legacy', 'legacy_hkdf')):
            fixture, packages, _ = api.FAMILIES[family]
            for matrix in (False, True):
                check, = [c for c in registry['checks'] if c['component'] == component
                          and c['id'] == ('public-api-matrix' if matrix else 'packaged-public-api')]
                self.assertEqual(check['command'],
                                 ['python3', 'scripts/hkdf/check-hkdf-public-api.py', '--family', family]
                                 + (['--matrix'] if matrix else []))
                groups = [registry['groups'][name] for name in check['inputs']]
                paths = {p for g in groups for p in g.get('paths', [])}
                self.assertTrue({f'crates/{p}' for p in packages} <= paths)
                self.assertTrue({f'assurance/{fixture}/src', f'assurance/{fixture}/Cargo.toml',
                                 f'assurance/{fixture}/Cargo.lock', 'Cargo.toml', 'Cargo.lock',
                                 'assurance/hkdf-public-api-common.rs',
                                 'scripts/hkdf/check-hkdf-public-api.py',
                                 'scripts/hkdf/test-hkdf-public-api.py',
                                 'scripts/repository/facade_cargo_environment.py'} <= paths)
                tools = {(t['program'], t.get('toolchain')) for g in groups for t in g.get('tools', [])}
                for compiler in (api.MATRIX if matrix else [api.MATRIX[0], api.MATRIX[-1]]):
                    for program in ('cargo', 'rustc'):
                        self.assertIn((program, compiler), tools)
                self.assertIn(('python3', None), tools)
                self.assertTrue(set(api.REJECT_ENV) <= set(check['reject_environment']))
                self.assertIn(f'HKDF packaged public API {family}: PASS; no upload', check['success']['contains'])
                if matrix:
                    self.assertIn(f'HKDF packaged public API {family}: MATRIX PASS; 14 host compilers', check['success']['contains'])

    def test_exact_diagnostic(self):
        self.assertTrue(api.diagnostic_matches(result(diagnostic()), 'E0308'))

    def test_unrelated_failure_is_not_a_negative_pass(self):
        for value in (result(), result(diagnostic('E0432')), result(diagnostic(), status=0),
                      result(diagnostic(filename='dependency/src/lib.rs')),
                      result(diagnostic(primary=False)),
                      result(diagnostic(), diagnostic()),
                      result({'reason': 'build-finished', 'success': False})):
            with self.subTest(value=value):
                self.assertFalse(api.diagnostic_matches(value, 'E0308'))

    def test_null_code_is_not_a_negative_pass(self):
        record = diagnostic()
        record['message']['code'] = None
        self.assertFalse(api.diagnostic_matches(result(record), 'E0308'))

    def test_invalid_json_is_not_a_pass(self):
        with self.assertRaises(ValueError):
            api.diagnostic_matches(subprocess.CompletedProcess([], 1, 'not JSON', ''), 'E0308')

    def test_negative_controls_have_distinct_valid_controls(self):
        for family, count in (('modern', 19), ('legacy', 16)):
            cases = api.probes(family)
            self.assertEqual(len(cases), count)
            self.assertEqual(len({c[0] for c in cases}), count)
            for _, negative, positive, code in cases:
                self.assertNotEqual(negative, positive)
                for item in ([code] if isinstance(code, str) else code):
                    self.assertRegex(item, r'^E\d{4}$')

    def test_sealed_probe_requires_both_supertrait_rejections(self):
        codes = ('E0277', 'E0277')
        self.assertTrue(api.diagnostic_matches(result(diagnostic('E0277'), diagnostic('E0277')), codes))
        for records in ((diagnostic('E0277'),), (diagnostic('E0277'), diagnostic('E0432')),
                        (diagnostic('E0277'), diagnostic('E0277', filename='dependency.rs'))):
            self.assertFalse(api.diagnostic_matches(result(*records), codes))

    def test_repeat_compiler_probe_directory_and_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            consumer = Path(temporary)
            (consumer / 'src').mkdir()
            with patch.object(api, 'run') as valid, patch.object(api.subprocess, 'run') as invalid, \
                    patch.object(api.cargo_environment, 'check') as config:
                invalid.side_effect = [result(*(diagnostic(code) for code in
                                       ([c[3]] if isinstance(c[3], str) else c[3])))
                                       for _ in range(2) for c in api.probes('modern')]
                for _ in range(2):
                    api.public_negatives('modern', consumer, ['cargo'], {})
                    self.assertFalse((consumer / 'src/bin/probe.rs').exists())
                self.assertEqual(valid.call_count, 38)
                self.assertEqual(invalid.call_count, 38)
                self.assertEqual(config.call_count, 38)

    def test_environment_allowlist_discards_open_ended_overrides(self):
        poison = {name: 'untrusted' for name in (
            'CARGO_BUILD_RUSTFLAGS', 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS',
            'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER',
            'CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS', 'CARGO_PROFILE_RELEASE_OPT_LEVEL',
            'CARGO_HOME', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_FUTURE_OPTION',
            'RUSTFLAGS', 'RUSTUP_TOOLCHAIN', 'RUSTC', 'LD_PRELOAD', 'TMPDIR')}
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, poison):
            root = Path(temporary)
            env = api.isolated_env(root)
            self.assertFalse(set(poison) & set(env) - {'CARGO_HOME'})
            self.assertEqual(Path(env['CARGO_HOME']), root / 'cargo-home')
            self.assertEqual(list(Path(env['CARGO_HOME']).iterdir()), [])
            self.assertEqual(env['CARGO_NET_OFFLINE'], 'true')
            self.assertEqual(env['RUSTUP_AUTO_INSTALL'], '0')

    def test_private_workspace_ignores_shared_temp_parent(self):
        with patch.dict(os.environ, {'TMPDIR': '/nonexistent/untrusted'}):
            with api.cargo_environment.private_directory(api.ROOT) as temporary:
                self.assertEqual(Path(temporary).parent, api.ROOT / 'target')
                self.assertEqual(Path(temporary).stat().st_mode & 0o077, 0)

    def test_config_poisoning_blocks_before_subprocess(self):
        for name in ('config', 'config.toml'):
            for location in ('ancestor', 'home'):
                for symlink in (False, True):
                    with self.subTest(name=name, location=location, symlink=symlink), \
                            api.cargo_environment.private_directory(api.ROOT) as temporary:
                        root = Path(temporary)
                        env = api.isolated_env(root)
                        consumer = root / 'consumer'
                        consumer.mkdir()
                        config = (root / '.cargo' if location == 'ancestor'
                                  else Path(env['CARGO_HOME'])) / name
                        config.parent.mkdir(exist_ok=True)
                        if symlink:
                            config.symlink_to(root / 'missing')
                        else:
                            config.write_text('[build]\nrustc-wrapper="evil"\n')
                        with patch.object(api.subprocess, 'run') as process:
                            with self.assertRaisesRegex(ValueError, 'ambient Cargo'):
                                api.run(['cargo', '--version'], consumer, env)
                            process.assert_not_called()

    def test_packaging_preserves_inherited_settings_without_unrelated_members(self):
        with api.cargo_environment.private_directory(api.ROOT) as temporary:
            workspace = api.package_workspace(Path(temporary), api.LEGACY)
            actual = tomllib.loads((workspace / 'Cargo.toml').read_text())
            original = tomllib.loads((api.ROOT / 'Cargo.toml').read_text())
            self.assertEqual(actual['workspace']['members'], [f'crates/{p}' for p in api.LEGACY])
            for key in ('package', 'lints', 'dependencies'):
                self.assertEqual(actual['workspace'][key], original['workspace'][key])
            self.assertEqual(actual['profile'], original['profile'])
            self.assertFalse((workspace / 'crates/brynja-sanitization').exists())

    def package_fixture(self, root, includes=None):
        root.mkdir()
        (root / 'src').mkdir()
        (root / 'Cargo.toml').write_text(
            '[package]\nname="package-selection-fixture"\nversion="0.0.0"\nedition="2024"\n'
            + ('include=' + json.dumps(includes) + '\n' if includes is not None else '')
            + '[workspace]\n')
        (root / 'src/lib.rs').write_text('mod ignored; pub fn value() -> u8 { ignored::value() }\n')
        (root / 'src/ignored.rs').write_text('pub fn value() -> u8 { 42 }\n')
        for name in ('LICENSE-APACHE', 'LICENSE-MIT', 'README.md'):
            (root / name).write_text('synthetic package documentation\n')
        (root / '.gitignore').write_text('*.key\nPENTEST.md\n/src/ignored.rs\n')
        for name in ('notes.key', 'PENTEST.md', 'notes.txt'):
            (root / name).write_text('synthetic unpublished input\n')
        return root

    def test_all_packaged_crates_have_reviewed_include_lists(self):
        for package in set(api.MODERN + api.LEGACY):
            paths = api.package_files(api.ROOT / 'crates' / package)
            self.assertIn(Path('src/lib.rs'), paths)
            self.assertTrue({Path(p) for p in ('LICENSE-APACHE', 'LICENSE-MIT', 'README.md')} <= paths)
            self.assertNotIn(Path('PENTEST.md'), paths)

    def test_package_inputs_exclude_unpublished_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.package_fixture(Path(temporary) / 'source', list(api.PACKAGE_INPUTS))
            self.assertEqual(api.package_files(root),
                             {Path(p) for p in ('Cargo.toml', 'src/lib.rs', 'src/ignored.rs',
                                               'LICENSE-APACHE', 'LICENSE-MIT', 'README.md')})

    def test_missing_package_documentation_stops_before_cargo(self):
        for name in ('LICENSE-APACHE', 'LICENSE-MIT', 'README.md'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                crate = self.package_fixture(base / 'source', list(api.PACKAGE_INPUTS))
                (crate / name).unlink()
                with patch.object(api, 'run') as process:
                    with self.assertRaisesRegex(ValueError, f'package lacks {name}'):
                        api.package_files(crate)
                    process.assert_not_called()

    def test_unreviewed_or_missing_include_list_fails_closed(self):
        for includes in (None, ['**/*'], [*api.PACKAGE_INPUTS, '*.key'],
                         [*api.PACKAGE_INPUTS, '../outside']):
            with self.subTest(includes=includes), tempfile.TemporaryDirectory() as temporary:
                root = self.package_fixture(Path(temporary) / 'source', includes)
                with self.assertRaisesRegex(ValueError, 'reviewed explicit include'):
                    api.package_files(root)

    def test_package_inputs_reject_symlinks(self):
        for name in ('Cargo.toml', 'src/ignored.rs', 'src/nested',
                     'LICENSE-APACHE', 'LICENSE-MIT', 'README.md'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = self.package_fixture(base / 'source', list(api.PACKAGE_INPUTS))
                target = root / name
                target.unlink(missing_ok=True)
                target.symlink_to(base / 'missing')
                with self.assertRaisesRegex(ValueError, 'symlink'):
                    api.package_files(root)

    def test_archive_selection_and_bytes_cannot_drift(self):
        for change in ('extra', 'missing', 'changed', 'manifest',
                       'LICENSE-APACHE', 'LICENSE-MIT', 'README.md'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                crate = self.package_fixture(base / 'source', list(api.PACKAGE_INPUTS))
                unpacked = base / 'unpacked'
                for path in api.package_files(crate):
                    dest = unpacked / path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes((crate / path).read_bytes())
                (unpacked / 'Cargo.toml.orig').write_bytes((crate / 'Cargo.toml').read_bytes())
                api.check_packaged_inputs(crate, unpacked)
                if change == 'extra':
                    (unpacked / 'notes.key').write_text('synthetic extra')
                elif change == 'missing':
                    (unpacked / 'src/ignored.rs').unlink()
                elif change in ('LICENSE-APACHE', 'LICENSE-MIT', 'README.md'):
                    (unpacked / change).unlink()
                else:
                    (unpacked / ('Cargo.toml.orig' if change == 'manifest' else 'src/lib.rs')).write_text('altered')
                with self.assertRaisesRegex(ValueError, 'archive'):
                    api.check_packaged_inputs(crate, unpacked)

    def test_real_cargo_git_and_private_archives_select_the_same_inputs(self):
        # Cargo's include policy overrides ignores, including ignored Rust inputs.
        # Exercise real archives, not a mocked file list or just filesystem copies.
        with api.cargo_environment.private_directory(api.ROOT) as temporary:
            base = Path(temporary)
            env = api.isolated_env(base)
            source = self.package_fixture(base / 'source', list(api.PACKAGE_INPUTS))
            git_env = {**env, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
            for args in (['init', '-q'], ['add', 'Cargo.toml', 'src/lib.rs', '.gitignore'],
                         ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                          '-c', 'core.hooksPath=' + os.devnull, 'commit', '-qm', 'fixture', '--no-gpg-sign']):
                subprocess.run(['git', *args], cwd=source, env=git_env, check=True,
                               capture_output=True, timeout=30)
            private = base / 'private'
            for path in api.package_files(source):
                dest = private / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((source / path).read_bytes())
            cargo = ['cargo', '+1.99.1']
            sets = []
            for name, crate in (('git', source), ('private', private)):
                selected_env = {**env, 'CARGO_TARGET_DIR': str(base / ('target-' + name))}
                api.run([*cargo, 'generate-lockfile', '--offline'], crate, selected_env)
                api.run([*cargo, 'package', '--locked', '--offline', '--allow-dirty', '--no-verify'],
                        crate, selected_env)
                prefix = 'package-selection-fixture-0.0.0'
                destination = base / ('unpacked-' + name)
                api.unpack(Path(selected_env['CARGO_TARGET_DIR']) / f'package/{prefix}.crate',
                           destination, prefix)
                api.check_packaged_inputs(source, destination / prefix)
                sets.append({p.relative_to(destination / prefix) for p in
                             (destination / prefix).rglob('*') if p.is_file()}
                            - {Path(p) for p in api.GENERATED_FILES})
            self.assertEqual(sets[0], sets[1])
            self.assertIn(Path('src/ignored.rs'), sets[0])
            self.assertNotIn(Path('notes.key'), sets[0])
            self.assertNotIn(Path('PENTEST.md'), sets[0])

    def test_family_rejects_unexpected_archive_before_consumer_build(self):
        unpack = api.unpack

        def poisoned(archive, destination, prefix):
            unpack(archive, destination, prefix)
            (destination / prefix / 'notes.key').write_text('synthetic injected member')

        with patch.object(api, 'unpack', side_effect=poisoned), \
                patch.object(api, 'packaged_graph') as graph:
            with self.assertRaisesRegex(ValueError, 'archive file selection'):
                api.check_family('legacy', ['1.99.1'], 'thumbv7em-none-eabi')
            graph.assert_not_called()

    def test_failed_positive_stops_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as temporary:
            consumer = Path(temporary)
            (consumer / 'src').mkdir()
            with patch.object(api, 'run', side_effect=ValueError('positive failed')), \
                    patch.object(api.subprocess, 'run') as invalid:
                with self.assertRaisesRegex(ValueError, 'positive failed'):
                    api.public_negatives('legacy', consumer, ['cargo'], {})
                invalid.assert_not_called()
            self.assertFalse((consumer / 'src/bin/probe.rs').exists())

    def archive(self, entries, destination):
        archive = destination / 'input.crate'
        with tarfile.open(archive, 'w') as handle:
            for name, kind in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = '../../outside'
                member.size = 2 if kind == tarfile.REGTYPE else 0
                handle.addfile(member, io.BytesIO(b'ok') if member.size else None)
        return archive

    def test_unpack_regular_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = self.archive([('pkg-1/src/lib.rs', tarfile.REGTYPE)], root)
            api.unpack(archive, root / 'unpacked', 'pkg-1')
            self.assertEqual((root / 'unpacked/pkg-1/src/lib.rs').read_bytes(), b'ok')

    def test_unpack_rejects_unsafe_or_ambiguous_entries(self):
        for entries in (
                [('../outside', tarfile.REGTYPE)], [('/absolute', tarfile.REGTYPE)],
                [('other-1/src/lib.rs', tarfile.REGTYPE)],
                [('pkg-1/../outside', tarfile.REGTYPE)],
                [('pkg-1/link', tarfile.SYMTYPE)], [('pkg-1/link', tarfile.LNKTYPE)],
                [('pkg-1/dir', tarfile.DIRTYPE)],
                [('pkg-1/one', tarfile.REGTYPE)] * 2):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with self.assertRaises(ValueError):
                    api.unpack(self.archive(entries, root), root / 'out', 'pkg-1')

    def test_matrix_matches_supported_host_catalog(self):
        script = (api.ROOT / 'scripts/ci/check-rust-version-matrix.sh').read_text()
        self.assertIn('toolchains=(' + ' '.join(api.MATRIX) + ')', script)

    def test_fixtures_are_separate_no_std_consumers(self):
        for family, (fixture, _, _) in api.FAMILIES.items():
            root = api.ROOT / 'assurance' / fixture
            manifest = tomllib.loads((root / 'Cargo.toml').read_text())
            expected = 'brynja' if family == 'modern' else 'brynja-legacy-hkdf'
            self.assertEqual(set(manifest['dependencies']), {expected})
            self.assertFalse(manifest['dependencies'][expected]['default-features'])
            self.assertFalse(manifest['package']['publish'])
            source = (root / 'src/lib.rs').read_text()
            self.assertIn('#![no_std]', source)
            self.assertIn('#![forbid(unsafe_code)]', source)
            self.assertNotIn('extern crate alloc', source)


if __name__ == '__main__':
    unittest.main()
