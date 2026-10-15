"""Focused scope mutations; fixtures never qualify a real CPU."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import native_review_io as io
import native_review_scope as scope
import native_tooling_review as tooling
import native_sha2_carry_forward as sha2
from native_review_tests import NativeReviewTests, write, commit, CODE, TEST


class ScopedNativeTests(NativeReviewTests):
    def test_exact_compiler_review_rebinding_does_not_relabel_native_results(self):
        old_checker, new_checker = b'old compiler inspector\n', b'new compiler inspector\n'
        for name, value in (('OLD', io.sha(old_checker)), ('NEW', io.sha(new_checker))):
            patcher = patch.object(tooling, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        original = ('REVIEWED_HASHES = {"' + tooling.CHECKER + '": "' + tooling.OLD +
                    '", "crates/example/src/lib.rs": "' + '0'*64 + '"}\n').encode()
        write(self.root, tooling.PATH, original.decode())
        write(self.root, tooling.CHECKER, old_checker.decode())
        before = commit(self.root)
        revised = original.replace(tooling.OLD.encode(), tooling.NEW.encode())
        write(self.root, tooling.PATH, revised.decode())
        write(self.root, tooling.CHECKER, new_checker.decode())
        after = commit(self.root)
        closure = {CODE, TEST, tooling.PATH}
        self.assertTrue(tooling.equivalent(self.root, before, after, tooling.PATH))
        scope.unchanged(self.root, before, after, closure)
        self.assertFalse(tooling.equivalent(self.root, before, after, CODE))
        # The exemption does not apply if the checker itself is a capture input.
        with self.assertRaises(ValueError):
            scope.unchanged(self.root, before, after, closure | {tooling.CHECKER})
        for name, raw in ((tooling.PATH, revised + b'print("changed")\n'),
                          (tooling.PATH, revised.replace(b'crates/', b'other/', 1)),
                          (tooling.PATH, revised.replace(tooling.NEW.encode(), b'0'*64)),
                          (tooling.CHECKER, new_checker + b'\n# changed\n'),
                          (CODE, b'pub fn changed_kernel() {}')):
            path = self.root / name
            saved = path.read_bytes()
            write(self.root, name, raw.decode())
            with self.subTest(name=name), self.assertRaises(ValueError):
                scope.unchanged(self.root, before, commit(self.root), closure)
            path.write_bytes(saved)
            commit(self.root)

    def scoped(self, head):
        from native_review_carry_forward import check_protected
        check_protected(self.root, self.doc, head, {CODE, TEST})

    def test_unrelated_crate_and_fixture_changes_do_not_invalidate_family(self):
        write(self.root, 'crates/unrelated/src/lib.rs', 'pub fn new_api() {}')
        write(self.root, 'assurance/unrelated/src/lib.rs', 'pub fn test_api() {}')
        self.scoped(commit(self.root))

    def test_family_addition_removal_build_flags_and_kernel_changes_block(self):
        for name in (CODE, TEST, 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                     '.cargo/config.toml', 'crates/example/build.rs',
                     'crates/example/Cargo.toml', 'crates/example/src/orphan.rs'):
            with self.subTest(name=name):
                path = self.root / name
                before = path.read_bytes() if path.exists() else None
                write(self.root, name, 'unreviewed change')
                with self.assertRaises((ValueError, KeyError)):
                    self.scoped(commit(self.root))
                if before is None:
                    path.unlink()
                else:
                    path.write_bytes(before)
                commit(self.root)
        (self.root / CODE).unlink()
        with self.assertRaises(ValueError):
            self.scoped(commit(self.root))

    def test_lock_projection_only_ignores_corroborated_facade_version(self):
        write(self.root, 'crates/brynja/Cargo.toml', '[package]\nversion="0.24.49"\n')
        old = 'version=4\n[[package]]\nname="brynja"\nversion="0.24.49"\ndependencies=["example"]\n'
        write(self.root, 'Cargo.lock', old)
        before = commit(self.root)
        write(self.root, 'crates/brynja/Cargo.toml', '[package]\nversion="0.24.50"\n')
        write(self.root, 'Cargo.lock', old.replace('0.24.49', '0.24.50'))
        scope.unchanged(self.root, before, commit(self.root), {CODE, TEST})
        write(self.root, 'Cargo.lock', old.replace('0.24.49', '0.24.50').replace('example', 'new-dependency'))
        with self.assertRaises(ValueError):
            scope.unchanged(self.root, before, commit(self.root), {CODE, TEST})


class InactiveSha2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='brynja-inactive-sha2-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for args in (('init', '-q'), ('config', 'user.name', 'Test'),
                     ('config', 'user.email', 'test@example.invalid')):
            io.git(self.root, *args)
        self.original = b'pub mod strict_tuplehash;\npub mod other;\n'
        write(self.root, sha2.LIB, self.original.decode())
        write(self.root, sha2.FIXTURE, '[package]\nname="fixture"\n')
        write(self.root, 'crates/brynja-hash-sha2/src/lib.rs', 'pub fn kernel() {}')
        self.capture = commit(self.root)
        self.captured = self.sources()
        write(self.root, sha2.LIB, self.original.replace(sha2.ANCHOR, sha2.ANCHOR + sha2.DECLARATION).decode())
        write(self.root, sha2.DIRECTORY + 'mod.rs', 'pub fn windows_only() {}')
        commit(self.root)

    def sources(self):
        return {name: sha2.evidence.source_digest(name, io.read(self.root, name))
                for name in io.names(self.root, io.git(self.root, 'rev-parse', 'HEAD').decode().strip())}

    def check(self):
        with patch.object(sha2, 'inactive') as inactive:
            sha2.equivalent(self.root, self.capture, self.sources(), self.captured)
            inactive.assert_called_once_with(self.root)

    def test_exact_inactive_addition_only(self):
        self.check()
        write(self.root, sha2.DIRECTORY + 'extra.rs', 'pub fn still_inactive() {}')
        commit(self.root)
        self.check()

    def test_guard_kernel_fixture_buildscript_and_missing_source_mutations_reject(self):
        mutations = [(sha2.LIB, self.original.decode() + 'pub mod windows_enclave;'),
                     (sha2.LIB, self.original.decode() + sha2.DECLARATION.decode()),
                     ('crates/brynja-hash-sha2/src/lib.rs', 'pub fn changed_kernel() {}'),
                     (sha2.FIXTURE, 'feature changed'),
                     ('crates/brynja-crypto-cpu-std/build.rs', 'fn main() {}'),
                     ('crates/brynja-hash-sha2/src/extra.rs', 'pub fn new_kernel() {}')]
        for name, value in mutations:
            path = self.root / name
            original = path.read_bytes() if path.exists() else None
            write(self.root, name, value)
            commit(self.root)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check()
            if original is None:
                path.unlink()
            else:
                path.write_bytes(original)
            commit(self.root)
        (self.root / sha2.FIXTURE).unlink()
        commit(self.root)
        with self.assertRaises(ValueError):
            self.check()

    def test_resolved_feature_union_and_package_origin_are_checked(self):
        package = {'name': 'brynja-crypto-cpu-std', 'id': 'hosted',
                   'manifest_path': str(self.root / 'crates/brynja-crypto-cpu-std/Cargo.toml')}
        graph = {'packages': [package], 'resolve': {'nodes': [{'id': 'hosted', 'features': ['runtime-execution']}]}}
        def check(value):
            result = subprocess.CompletedProcess([], 0, json.dumps(value).encode())
            with patch.object(sha2.subprocess, 'run', return_value=result) as run:
                sha2.inactive(self.root)
                self.assertIn('--locked', run.call_args.args[0])
                self.assertIn('--offline', run.call_args.args[0])
        check(graph)
        for mutate in (lambda g: g['resolve']['nodes'][0]['features'].append('strict-sha2'),
                       lambda g: g['packages'].append(dict(package)),
                       lambda g: g['packages'][0].update(manifest_path='/other/Cargo.toml'),
                       lambda g: g['resolve'].update(nodes=[])):
            changed = copy.deepcopy(graph)
            mutate(changed)
            with self.assertRaises(ValueError):
                check(changed)

    def test_full_fallback_retains_original_lane_result_and_review_validation(self):
        path = io.ROOT / 'scripts/sha2/test-sha2-hardened-native.py'
        spec = importlib.util.spec_from_file_location('sha2_capture_fixture', path)
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        current = self.sources()
        index = {'schema': 1, 'capture_commit': self.capture, 'lanes': {}}
        records = {}
        for lane in sha2.evidence.LANES:
            name = 'assurance/sha2-hardened-native/' + lane + '.json'
            record = fixture.artifact(lane, self.capture, self.captured)
            raw = json.dumps(record)
            write(self.root, name, raw)
            records[lane] = record
            index['lanes'][lane] = {'artifact': name, 'sha256': io.sha(raw.encode()),
                                    'reviewed': True, 'cpu': record['cpu']}
        def run(value):
            write(self.root, sha2.evidence.INDEX, json.dumps(value))
            commit(self.root)
            with patch.object(sha2.evidence, 'sources', return_value=current), \
                 patch.object(sha2, 'inactive'):
                sha2.validate(self.root)
        run(index)
        for lane in index['lanes']:
            for key, value in (('reviewed', False), ('cpu', 'wrong'), ('sha256', '0' * 64)):
                changed = copy.deepcopy(index)
                changed['lanes'][lane][key] = value
                with self.subTest(lane=lane, key=key), self.assertRaises(ValueError):
                    run(changed)
            changed = copy.deepcopy(index)
            changed['lanes'].pop(lane)
            with self.assertRaises(ValueError):
                run(changed)
            record = copy.deepcopy(records[lane])
            record['results']['kernel_tests'] = 'test result: ok. 0 passed'
            raw = json.dumps(record)
            name = index['lanes'][lane]['artifact']
            write(self.root, name, raw)
            changed = copy.deepcopy(index)
            changed['lanes'][lane]['sha256'] = io.sha(raw.encode())
            with self.assertRaises(ValueError):
                run(changed)
            write(self.root, name, json.dumps(records[lane]))
        run(index)
