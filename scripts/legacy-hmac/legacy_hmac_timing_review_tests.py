"""Saved timing review rejects corruption/drift, without asserting authenticity."""
import copy
from contextlib import nullcontext
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import legacy_hmac_timing as timing
import legacy_hmac_timing_review as review


def manifests():
    root = b'[workspace]\nmembers=["crates/*"]\n[workspace.dependencies]\n'
    leaf = b'[package]\nname="brynja-legacy-hmac"\nversion="0.1.0"\n[dependencies]\n'
    new_root, new_leaf = root, leaf
    for name in ('brynja-legacy-md5', 'brynja-legacy-sha1'):
        leaf += f'{name}={{path="../{name}",version="=0.1.0",default-features=false}}\n'.encode()
        new_root += f'{name}={{path="crates/{name}",version="=0.1.0",default-features=false}}\n'.encode()
        new_leaf += f'{name}={{workspace=true,default-features=false}}\n'.encode()
    before = {'Cargo.toml': root, 'crates/brynja-legacy-hmac/Cargo.toml': leaf,
              'crates/brynja-legacy-hmac/src/lib.rs': b'// synthetic implementation\n'}
    return before, {**before, 'Cargo.toml': new_root, 'crates/brynja-legacy-hmac/Cargo.toml': new_leaf}


def document(route='portable', family='md5', target='x86_64-unknown-linux-gnu', signal=False):
    arch = 'aarch64' if target == 'aarch64-apple-darwin' else 'x86_64'
    lines = []
    for width in (10, timing.WIDTHS[family]):
        for key in (32, 200):
            for mode in ('verify', 'key'):
                lines.extend(f'SAMPLE {family} {mode} {key} {width} {i} 100 {99 if signal else 100}'
                             for i in range(timing.SAMPLES))
    output = '\n'.join([*lines, timing.marker(route, family, arch)]) + '\n'
    rows = timing.parse(output, route, family, arch)
    flags, probe = '-C target-cpu=generic', None
    if route in timing.COMPILED:
        flags += ' -C target-feature=' + ({'md5': '+avx2', 'sha1': '+sha,+sse2'} if arch == 'x86_64'
                                         else {'md5': '+neon', 'sha1': '+neon,+sha2'})[family]
        probe = {'command': ['/synthetic/generic-host-probe', family],
                 'compile_command': ['rustc', '+1.99.1', '--edition=2024', '-C', 'target-cpu=generic',
                                     '/synthetic/assurance/legacy-hmac-timing/host_probe.rs',
                                     '-o', '/synthetic/generic-host-probe'],
                 'output': 'LEGACY_HMAC_HOST_FEATURES: ' + family + '\n'}
    return {'schema': 1, 'kind': 'author-operated-legacy-hmac-timing-observation',
            'claim': 'synthetic test data, NOT execution evidence', 'measurement_scope': 'synthetic',
            'route': route, 'family': family, 'host': 'macOS-test' if arch == 'aarch64' else 'Linux-test',
            'machine': arch, 'head': 'a' * 40,
            'sources_sha256': {name: review.sha(raw) for name, raw in manifests()[0].items()},
            'compiler': 'rustc 1.99.1 (synthetic)\nbinary: rustc\ncommit-hash: synthetic\ncommit-date: synthetic\n'
                        'host: ' + target + '\nrelease: 1.99.1\nLLVM version: synthetic',
            'compiler_binary_sha256': 'b' * 64, 'binary_sha256': 'c' * 64,
            'build_command': ['cargo', '+1.99.1', 'build', '--release', '--locked', '--offline',
                              '--manifest-path', '/synthetic/assurance/legacy-hmac-timing/Cargo.toml'],
            'build_rustflags': flags, 'generic_host_probe': probe,
            'command': ['/synthetic/release/brynja-legacy-hmac-timing', route, family],
            'exit_status': 0, 'raw_stderr': '', 'raw_output': output, 'output_sha256': review.sha(output.encode()),
            'failure': None, 'campaigns': rows, 'signals': sum(row['signal'] for row in rows),
            'samples_per_class': timing.SAMPLES, 'repetitions': timing.REPEAT, 'alarm_threshold': timing.LIMIT}


class ReviewTests(unittest.TestCase):
    def validate(self, data, current=None, anchor=None, captured=None):
        before, after = manifests()
        return review.validate(data, data['route'], data['family'],
                               'aarch64-apple-darwin' if data['machine'] == 'aarch64' else 'x86_64-unknown-linux-gnu',
                               current if current is not None else after,
                               anchor if anchor is not None else before,
                               captured if captured is not None else before)

    def test_review_all_routes_without_relabeling_capture_or_granting_approval(self):
        for target, routes in (('x86_64-unknown-linux-gnu', ('portable', 'static', 'linux-protected', 'linux-compiled')),
                               ('aarch64-apple-darwin', ('portable', 'static', 'macos-resident', 'macos-compiled'))):
            for route in routes:
                for family in ('md5', 'sha1'):
                    data = document(route, family, target)
                    result = self.validate(data)
                    self.assertEqual(result['current_manifest_changes'], sorted(review.MANIFESTS))
                    self.assertEqual(result['capture_head'], 'a' * 40)
                    self.assertEqual(result['capture_head_mismatches'], [])
                    self.assertIn('NOT release approval', result['status'])
        data = document()
        original = copy.deepcopy(data)
        result = self.validate(data, captured={})
        self.assertEqual(result['capture_head_mismatches'], sorted(manifests()[0]))
        self.assertEqual(data, original)
        self.assertEqual(self.validate(data, current=manifests()[0])['current_manifest_changes'], [])

    def test_review_recomputes_statistics_and_preserves_signal_failure(self):
        data = document()
        mutations = [('exit_status', 1), ('exit_status', False), ('failure', 'interrupted'),
                     ('raw_stderr', 'unexpected'), ('signals', 1), ('signals', False),
                     ('output_sha256', '0' * 64), ('samples_per_class', 511), ('repetitions', 1),
                     ('alarm_threshold', 99), ('campaigns', data['campaigns'][:-1]),
                     ('raw_output', data['raw_output'] + 'extra\n'), ('schema', True)]
        for key, value in mutations:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate({**data, key: value})
        changed = copy.deepcopy(data)
        changed['campaigns'][0]['class0_mean_ns'] += 1
        with self.assertRaisesRegex(ValueError, 'statistics'):
            self.validate(changed)
        with self.assertRaisesRegex(ValueError, 'signal remains unresolved'):
            self.validate(document(signal=True))

    def test_review_rejects_source_changes_even_with_rehashed_current_data(self):
        before, after = manifests()
        data = document()
        source = 'crates/brynja-legacy-hmac/src/lib.rs'
        for current in ({**after, source: b'changed implementation'},
                        {**after, 'extra.rs': b'new code'}, {k: v for k, v in after.items() if k != source}):
            with self.assertRaises(ValueError):
                self.validate(data, current=current)
        changed = copy.deepcopy(data)
        changed['sources_sha256'][source] = review.sha(b'changed implementation')
        with self.assertRaisesRegex(ValueError, 'anchor'):
            self.validate(changed, current={**after, source: b'changed implementation'})
        with self.assertRaisesRegex(ValueError, 'anchor'):
            self.validate(data, anchor={**before, source: b'wrong anchor'})

    def test_review_manifest_equivalence_is_narrow_and_byte_changes_visible(self):
        before, after = manifests()
        for name, old, new in (
                ('Cargo.toml', b'=0.1.0', b'=0.2.0'),
                ('Cargo.toml', b'default-features=false', b'default-features=true'),
                ('Cargo.toml', b'crates/brynja-legacy-md5', b'crates/other'),
                ('Cargo.toml', b'[workspace]', b'[profile.release]\nopt-level=0\n[workspace]'),
                ('crates/brynja-legacy-hmac/Cargo.toml', b'workspace=true', b'workspace=false'),
                ('crates/brynja-legacy-hmac/Cargo.toml', b'default-features=false', b'default-features=true')):
            self.assertIn(old, after[name])
            with self.subTest(name=name, old=old), self.assertRaises(ValueError):
                self.validate(document(), current={**after, name: after[name].replace(old, new, 1)})
        # Non-manifest CRLF changes are real source drift, not normalized away.
        name = 'crates/brynja-legacy-hmac/src/lib.rs'
        with self.assertRaisesRegex(ValueError, 'source changed'):
            self.validate(document(), current={**after, name: after[name].replace(b'\n', b'\r\n')})

    def test_review_host_commands_and_feature_identity(self):
        data = document('static')
        for key, value in (('host', 'macOS-wrong'), ('build_rustflags', '-C target-cpu=native'),
                           ('generic_host_probe', None), ('compiler', 'rustc 1.90.0'),
                           ('command', ['/synthetic/other', 'static', 'md5']),
                           ('build_command', data['build_command'][:-1]), ('head', 'HEAD')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate({**data, key: value})
        with self.assertRaisesRegex(ValueError, 'route/family'):
            review.validate(data, 'static', 'sha1', 'x86_64-unknown-linux-gnu', *[manifests()[0]] * 3)
        changed = copy.deepcopy(data)
        changed['generic_host_probe']['compile_command'][4] = 'target-cpu=native'
        with self.assertRaisesRegex(ValueError, 'probe command'):
            self.validate(changed)

    def test_review_json_and_dirty_candidate_fail_closed_without_running(self):
        raw = json.dumps(document()).encode()
        self.assertEqual(review.load(raw), document())
        for bad in (raw.replace(b'"schema": 1', b'"schema": 1, "schema": 1'),
                    raw.replace(b'"signals": 0', b'"signals": NaN'), b'{}', b' ' * (2 * 1024 * 1024 + 1)):
            with self.assertRaises(ValueError):
                review.load(bad)
        spec = importlib.util.spec_from_file_location('review_driver', Path(__file__).with_name('review-legacy-hmac-timing.py'))
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        with patch.object(driver, 'git', return_value=b' M implementation.rs'), \
                patch.object(driver.runner, 'sources', side_effect=AssertionError('must reject before Cargo')):
            with self.assertRaisesRegex(ValueError, 'commit the candidate'):
                driver.collect(Path('/unused'), Path('/unused'), 'a' * 40)

    def test_review_requires_both_complete_host_populations(self):
        spec = importlib.util.spec_from_file_location('review_driver', Path(__file__).with_name('review-legacy-hmac-timing.py'))
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        before, after = manifests()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for name, data in after.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            for name in ('review.py', 'driver.py'):
                (root / name).write_text('# synthetic reviewer identity\n')
            linux, apple = root / 'linux', root / 'apple'
            for directory, target, routes, prefix in (
                    (linux, 'x86_64-unknown-linux-gnu', ('portable', 'static', 'linux-protected', 'linux-compiled'), 'linux-'),
                    (apple, 'aarch64-apple-darwin', ('portable', 'static', 'macos-resident', 'macos-compiled'), '')):
                directory.mkdir()
                for route in routes:
                    for family in ('md5', 'sha1'):
                        (directory / (prefix + route + '-' + family + '.json')).write_text(json.dumps(document(route, family, target)))
            def git(*args):
                return b'e' * 40 + b'\n' if args[0] == 'rev-parse' else b''
            with patch.object(driver, 'git', side_effect=git), patch.object(driver, 'blobs', return_value=before), \
                    patch.object(driver.runner, 'ROOT', root), patch.object(driver, '__file__', str(root / 'driver.py')), \
                    patch.object(review, '__file__', str(root / 'review.py')), \
                    patch.object(driver.runner.cargo_environment, 'private_directory', return_value=nullcontext(root)), \
                    patch.object(driver.runner, 'environment', return_value={}), \
                    patch.object(driver.runner, 'sources', return_value={n: review.sha(v) for n, v in after.items()}):
                result = driver.collect(linux, apple, 'd' * 40)
                self.assertEqual(len(result['observations']), 16)
                self.assertEqual(result['candidate'], 'e' * 40)
                extra = linux / 'failed-attempt.json'
                extra.write_text('{}')
                with self.assertRaisesRegex(ValueError, 'extra host observations'):
                    driver.collect(linux, apple, 'd' * 40)
                extra.unlink()
                (apple / 'static-md5.json').unlink()
                with self.assertRaisesRegex(ValueError, 'missing or extra'):
                    driver.collect(linux, apple, 'd' * 40)
