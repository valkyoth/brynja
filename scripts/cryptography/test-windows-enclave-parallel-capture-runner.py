"""Runner bookkeeping regressions only; mocked commands are never native evidence."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import windows_enclave_parallel_concurrent_host as runner


class Capture(unittest.TestCase):
    def exercise(self, failure=None):
        with tempfile.TemporaryDirectory(prefix='brynja-parallel-runner-') as directory:
            root = Path(directory)
            native = root/'crates/brynja-crypto-cpu-std/src/windows_enclave/native/parallel_concurrent'
            native.mkdir(parents=True)
            original = {}
            for name in ('mod.rs', 'callbacks.rs'):
                source = runner.ROOT/native.relative_to(root)/name
                shutil.copyfile(source, native/name)
                original[name] = (native/name).read_bytes()
            image = root/'signed.dll'; image.write_bytes(b'synthetic image, never executed')
            out = root/'results'
            binary = root/'synthetic.exe'; binary.write_bytes(b'synthetic binary, never executed')

            def execute(command, **kwargs):
                code, output = 0, ''
                if command[0] == 'rustc': output = 'synthetic compiler for runner unit test'
                elif command[0] == 'cargo' and 'test' in command:
                    if failure == 'compile' and any((native/n).read_bytes() != b for n,b in original.items()):
                        code = 1
                    output = json.dumps({'reason':'compiler-artifact', 'executable':str(binary)})+'\n'
                elif command[0] == 'cargo':
                    code = 1 if failure == 'clippy' else 0
                else:
                    mutant = Path(command[0]).name.startswith('mutant-')
                    if mutant:
                        code = 0 if failure == 'escaped' else 101
                        output = 'test result: FAILED.' if failure != 'crash' else 'abnormal termination'
                    elif runner.NATIVE_TEST in command:
                        output = ('cases=67;' if failure == 'population' else 'cases=68;')+'\n1 passed; 0 failed'
                    else:
                        output = 'running 0 tests\n0 failed' if failure == 'empty' else 'running 86 tests\n86 passed; 0 failed'
                return subprocess.CompletedProcess(command, code, output, '')

            snapshots = [{'synthetic':'before'}, {'synthetic':'after' if failure == 'drift' else 'before'}]
            with patch.object(runner, 'ROOT', root), patch.object(runner.sys, 'platform', 'win32'), \
                 patch.object(runner, 'sources', side_effect=snapshots), \
                 patch.object(runner, 'vectors', side_effect=lambda p:p.write_text('synthetic oracle rows')), \
                 patch.object(runner.subprocess, 'run', side_effect=execute):
                if failure:
                    with self.assertRaises((RuntimeError, ValueError)):
                        runner.capture(image, out)
                else:
                    runner.capture(image, out)
            for name, data in original.items():
                self.assertEqual((native/name).read_bytes(), data, 'mutations must be restored even on failure')
            record = json.loads((out/'host-results.json').read_text())
            self.assertEqual(record['status'], 'RUNNING' if failure else 'CRATE_PARALLEL_CONCURRENT_DEVELOPMENT_PASS')
            self.assertFalse(record['production_qualified'])
            if not failure:
                self.assertEqual(len(record['mutations']), 5)
                self.assertEqual(len(record['binaries']), 8)
                for row in record['commands']:
                    for stream in ('stdout','stderr'):
                        self.assertEqual(row[stream+'_sha256'], runner.digest(out/(row['label']+'.'+stream)))

    def test_success_saves_complete_bound_artifacts(self): self.exercise()
    def test_compile_error_is_not_mutant_rejection(self): self.exercise('compile')
    def test_escaped_mutant_rejects(self): self.exercise('escaped')
    def test_crash_is_not_an_assertion_failure(self): self.exercise('crash')
    def test_missing_population_rejects(self): self.exercise('population')
    def test_empty_lifecycle_rejects(self): self.exercise('empty')
    def test_clippy_error_rejects(self): self.exercise('clippy')
    def test_source_drift_rejects(self): self.exercise('drift')


if __name__ == '__main__': unittest.main()
