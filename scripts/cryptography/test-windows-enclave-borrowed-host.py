#!/usr/bin/env python3
"""Actual private adapter lifetime/ledger tests, not native platform qualification."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_borrowed_host_build as build
import windows_enclave_borrowed_host_run as native


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='brynja-borrowed-host-')
        cls.path = Path(cls.temporary.name)
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        target = next(line[6:] for line in identity.splitlines() if line.startswith('host: '))
        build.prepare(cls.path, target)
        cls.common = ['rustc', '+1.98.1', '--edition=2024', '-L', 'dependency=' + str(cls.path),
                      '--extern', 'enclave_borrowed=' + str(cls.path / 'libenclave_borrowed.rlib')]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_ledger_metadata_and_mutants(self):
        source = self.path / 'test.rs'
        source.write_text('#[path="native_model.rs"] mod model;\n')
        expected = 'native_bridge_never_commits_uncertain_output_or_reuses_owner ... FAILED'
        for level in ('0', '2'):
            for mutant in (None, 'probe_host_ignore_cleanup', 'probe_host_commit_early'):
                binary = self.path / ('test.exe' if os.name == 'nt' else 'test')
                command = self.common + ['--test', '-C', 'opt-level=' + level, str(source), '-o', str(binary)]
                if mutant:
                    command += ['--cfg', mutant]
                result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                if mutant:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stdout)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('5 passed', result.stdout)

    def test_source_borrow_survives_pending_drop_and_forget(self):
        def compile(body):
            source = self.path / 'consumer.rs'
            source.write_text('#[path="native_model.rs"] mod model;\n'
                              'use model::{Session, PublicInput, Disposition};\n' + body)
            return subprocess.run(self.common + ['--crate-type', 'lib', '--emit=metadata',
                str(source), '-o', str(self.path / 'consumer.rmeta')],
                capture_output=True, text=True, timeout=30)
        setup = ('let mut data = [0x5a; 32]; let mut session = Session::new(); '
                 'let mut pending = session.prepare(PublicInput::acknowledge(&data), Disposition::Cancel).unwrap(); '
                 'let request = pending.native_request(4096, 0).unwrap(); ')
        positive = compile('fn ok() { ' + setup + 'drop(pending); let _ = request.metadata(); }')
        self.assertEqual(positive.returncode, 0, positive.stderr)
        for ending in ('drop(pending);', 'core::mem::forget(pending);'):
            result = compile('fn bad() { ' + setup + ending + ' data[0] = 2; let _ = request.metadata(); }')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('E0506', result.stderr)
        result = compile("fn bad() -> enclave_borrowed::Request<'static> { " + setup + 'request }')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('E0515', result.stderr)
        for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            result = compile('fn bound<T: ' + bound + '>() {} fn bad() { '
                             "bound::<enclave_borrowed::Request<'static>>(); }")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('E0277', result.stderr)

    def test_generation_excludes_payload_serializer_and_rejects_anchor_drift(self):
        wire = (self.path / 'host_session_wire.rs').read_text()
        self.assertNotIn('1072', wire)
        self.assertNotIn('copy_from_slice(self.input.0)', wire)
        self.assertNotIn('fn enter(', wire)
        self.assertIn('request.metadata().as_ptr()', (self.path / 'native_host.rs').read_text())
        self.assertIn('Request::new(self.input.0, command)', (self.path / 'native_model.rs').read_text())
        for original in ('', 'anchor anchor'):
            with self.assertRaises(ValueError):
                build.replace_once(original, 'anchor', 'replacement')

    def test_exact_native_counter_rejections(self):
        for variant in native.VARIANTS + native.MUTANTS:
            if variant == 'normal':
                value = dict(result=0, created=6, deleted=6, calls=64, retained=0, cleanup_errors=0)
            elif variant == 'fail-delete':
                value = dict(result=14, created=1, deleted=0, calls=60, retained=1, cleanup_errors=2)
            elif variant in native.MUTANTS:
                count = {'early': 3, 'cleanup': 4, 'copy-proof': 5}[variant]
                value = dict(result=21, created=count, deleted=count, calls=59 + count,
                             retained=0, cleanup_errors=0)
            else:
                value = dict(result=10, created=1, deleted=1, calls=0, retained=0, cleanup_errors=0)
            native.validate(value, variant)
            for key in value:
                for bad in (value[key] + 1, str(value[key]), bool(value[key])):
                    with self.assertRaises(ValueError):
                        native.validate({**value, key: bad}, variant)
            with self.assertRaises(ValueError):
                native.validate({**value, 'extra': 0}, variant)

    @unittest.skipIf(os.name == 'nt', 'local C compiler shim; real MSVC host tested separately')
    def test_generated_c_main_requires_updated_exact_counters(self):
        source = (self.path / 'native_host_main.c').read_text()
        source = build.replace_once(source, '#include "native_host.h"',
            '#include <stdint.h>\nuint64_t HostCounter(uint64_t which);')
        source += """
static uint64_t counters[5] = {6,6,64,0,0};
uint64_t HostCounter(uint64_t which) { return counters[which]; }
uint32_t HostCampaign(const wchar_t *image, size_t length) {
    (void)image; (void)length; return 0;
}
int main(void) {
    wchar_t *arguments[2] = {L"probe", L"image"};
    unsigned i;
    if (wmain(2, arguments) != 0) return 1;
    for (i=0; i<5; ++i) {
        counters[i]++;
        if (wmain(2, arguments) != 97) return 2;
        counters[i]--;
    }
    counters[0]=5; counters[1]=5; counters[2]=63;
    return wmain(2, arguments) == 97 ? 0 : 3;
}
"""
        path = self.path / 'main-counter.c'
        path.write_text(source)
        binary = self.path / 'main-counter'
        # GCC's uint64_t is unsigned long here, while MSVC uses unsigned long long.
        # Use the Windows printf argument width in the stub to preserve /Werror.
        path.write_text(source.replace('uint64_t HostCounter(', 'unsigned long long HostCounter('))
        result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
            str(path), '-o', str(binary)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
