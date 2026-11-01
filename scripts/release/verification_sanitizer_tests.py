"""Finite sanitizer registration checks; no Cargo/test/CPU execution."""
import copy
import json
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = {'brynja-core', 'brynja-hash-core'}


def validate(registry):
    catalog = json.loads((ROOT / 'verification/catalog.json').read_text())
    rows = {r['id']: r for r in catalog['entries'] if r['phase'] == 'asan'}
    # This validator owns the historical catalog bindings. New HKDF runs have
    # separate exact-command/population regressions in RegistryTests.
    checks = [c for c in registry['checks'] if c.get('category') == 'asan'
              and c['component'] not in ('hkdf', 'legacy_hkdf')]
    assert len(checks) == 32
    assert len({c['id'] for c in checks}) == 32
    for check in checks:
        original = rows[check['id']]
        assert original['families'] == [check['component']]
        command = check['command']
        native = command[0] == 'python3'
        if native:
            assert command == original['command']
            assert command[1] in ('scripts/md5/check-md5-execution-asan.py', 'scripts/md5/check-md5-hardened-asan.py')
            package = 'brynja-legacy-md5'
            assert check['success']['contains'][0].startswith('Native ')
            assert 'AVX2 ASan and LeakSanitizer: PASS' in check['success']['contains'][0]
        else:
            assert command[:3] == ['cargo', '+nightly-2026-09-11', 'test']
            assert command[3:5] == ['--locked', '--offline']
            assert command[:3] + command[5:] == original['command']
            package = command[command.index('-p') + 1]
            assert check['environment']['RUSTFLAGS'] == '-Zsanitizer=address'
            assert check['environment']['CARGO_ENCODED_RUSTFLAGS'] == ''
        assert check['platform'] == 'linux-x86_64'
        assert check['environment']['ASAN_OPTIONS'] == 'detect_leaks=1:halt_on_error=1:exitcode=1'
        assert check['environment']['LSAN_OPTIONS'] == 'exitcode=23'
        assert check['environment']['RUSTUP_AUTO_INSTALL'] == '0'
        assert check['success']['minimum_tests'] >= 1
        groups = [registry['groups'][g] for g in check['inputs']]
        paths = {p for g in groups for p in g.get('paths', [])}
        optional = {p for g in groups for p in g.get('optional_paths', [])}
        manifests = {p for g in groups for p in g.get('toml', {})}
        locks = {p for g in groups for lock in g.get('locks', []) for p in lock['packages']}
        expected = {package} if package == 'brynja-core' else BASE | {package}
        features = command[command.index('--features') + 1] if '--features' in command else ''
        if package in ('brynja-mac-kmac', 'brynja-hash-tuple'):
            expected.add('brynja-hash-sha3')
        if features and features != 'general-sha512-t' and not package.startswith('brynja-legacy-'):
            expected.add('brynja-crypto-cpu')
        if package in ('brynja-hash-parallel', 'brynja-hash-parallel-std'):
            expected |= {'brynja-hash-parallel', 'brynja-hash-sha3', 'brynja-hash-sha2', 'brynja-crypto-cpu', 'brynja-crypto-cpu-std'}
        assert locks == expected, (check['id'], locks, expected)
        for dependency in expected:
            assert f'crates/{dependency}/src' in paths
            assert f'crates/{dependency}/build.rs' in optional
            manifest = f'crates/{dependency}/Cargo.toml'
            assert manifest in manifests
            # Check explicit build closures, not a new automatic graph resolver.
            doc = tomllib.loads((ROOT / manifest).read_text())
            for section in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                for name, value in doc.get(section, {}).items():
                    if not value.get('optional', False):
                        assert name in expected, (check['id'], name)
        assert f'crates/{package}/tests' in paths
        if native:
            assert command[1] in paths
        assert all((ROOT / p).exists() for p in paths)
        tools = {(t['program'], t.get('toolchain')) for g in groups for t in g.get('tools', [])}
        assert {('cargo', 'nightly-2026-09-11'), ('rustc', 'nightly-2026-09-11')} <= tools
        if native:
            assert ('python3', None) in tools


class SanitizerRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = tomllib.loads((ROOT / 'verification/checks.toml').read_text())

    def test_explicit_commands_and_closures(self):
        validate(self.registry)

    def test_weakened_flags_population_or_input_scope_are_rejected(self):
        first = next(c for c in self.registry['checks'] if c.get('category') == 'asan'
                     and c['component'] not in ('hkdf', 'legacy_hkdf'))
        for path, value in [('platform', 'macos-aarch64'), ('inputs', ['asan-tools'])]:
            changed = copy.deepcopy(self.registry)
            next(c for c in changed['checks'] if c['id'] == first['id'])[path] = value
            with self.assertRaises(AssertionError):
                validate(changed)
        for section, key, value in [('environment', 'ASAN_OPTIONS', 'detect_leaks=0'), ('success', 'minimum_tests', 0)]:
            changed = copy.deepcopy(self.registry)
            next(c for c in changed['checks'] if c['id'] == first['id'])[section][key] = value
            with self.assertRaises(AssertionError):
                validate(changed)
