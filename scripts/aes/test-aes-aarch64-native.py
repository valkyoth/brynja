#!/usr/bin/env python3
"""Controls for native ARM correctness; these do not qualify ARM machine code."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_native', Path(__file__).with_name('check-aes-aarch64-native.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def elf():
    data = bytearray(64)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQ', data, 16, 3, 183, 1, 4096)
    return bytes(data)


class Aarch64NativeTests(unittest.TestCase):
    def test_only_final_arm_elf_is_accepted(self):
        native.elf_check(elf())
        for offset, value in ((0, 0), (4, 1), (5, 2), (6, 0), (16, 1), (18, 62), (20, 0), (25, 0)):
            data = bytearray(elf())
            data[offset] = value
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                native.elf_check(data)
        with self.assertRaises(ValueError):
            native.elf_check(elf()[:63])

    def test_markers_do_not_claim_timing_or_machine_review(self):
        for compiler in native.packaged.consumer.TOOLCHAINS:
            for route in ('direct', 'facade'):
                for panic, count in (('abort', 0), ('unwind', 48)):
                    marker = native.marker(compiler, route, panic)
                    self.assertIn(f'{count} caller unwinds', marker)
                    self.assertIn('machine-code qualification not claimed', marker)
        for config in (('stable', 'direct', 'abort'), ('1.90.0', 'cpu', 'abort'), ('1.90.0', 'direct', 'other')):
            with self.assertRaises(ValueError):
                native.marker(*config)

    def test_native_host_and_environment_checked_before_build(self):
        with patch.object(native, 'build') as build:
            with patch.object(native.platform, 'machine', return_value='x86_64'), self.assertRaisesRegex(ValueError, 'native Linux'):
                native.check('1.90.0')
            with patch.object(native.platform, 'system', return_value='Linux'), \
                    patch.object(native.platform, 'machine', return_value='aarch64'):
                for name in native.linked.REJECT:
                    with patch.dict(os.environ, {name: 'override'}, clear=True), self.assertRaisesRegex(ValueError, 'remove ambient'):
                        native.check('1.90.0')
                with patch.dict(os.environ, {}, clear=True), patch.object(native.shutil, 'which', return_value=None), \
                        self.assertRaisesRegex(ValueError, 'missing llvm-nm'):
                    native.check('1.90.0')
            build.assert_not_called()

    def test_build_pins_target_profile_graph_and_both_binaries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(native.packaged.archives, 'run', return_value=SimpleNamespace(stdout='{}')) as run, \
                    patch.object(native.packaged, 'graph') as graph:
                binaries, env = native.build(root, root / 'consumer', {}, '1.90.0', 'direct', 'unwind', {})
                graph.assert_called_once_with({}, 'direct', root / 'consumer', root / 'unpacked', {})
                self.assertEqual(env['CARGO_PROFILE_RELEASE_PANIC'], 'unwind')
                self.assertEqual(binaries, root / 'arm-1.90.0-direct-unwind' / native.TARGET / 'release')
                for call in run.call_args_list:
                    command = call.args[0]
                    self.assertIn('--locked', command)
                    self.assertIn('--offline', command)
                    self.assertIn(native.TARGET, command)
                command = run.call_args.args[0]
                self.assertEqual(command.count('--bin'), 2)
                self.assertIn('linked', command)
                self.assertIn('lifecycle', command)

    def test_bad_image_rejected_before_tools_or_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            binary = directory / 'linked'
            binary.write_bytes(b'not an ELF')
            with patch.object(native.packaged.archives, 'run') as run, self.assertRaises(ValueError):
                native.observe(binary, directory, {}, {}, directory)
            run.assert_not_called()

    def test_native_completion_requires_exact_kat_and_lifecycle_populations(self):
        good = '\n'.join(native.linked.KAT_LINES)
        native.linked.output_check(good)
        for output in ('', good + '\n' + good, good.replace('256', '128')):
            with self.assertRaises(ValueError):
                native.linked.output_check(output)
        for panic in ('abort', 'unwind'):
            good = '\n'.join(native.lifecycle.output_lines(panic))
            native.lifecycle.output_check(good, panic)
            with self.assertRaises(ValueError):
                native.lifecycle.output_check(good, 'abort' if panic == 'unwind' else 'unwind')

    def test_artifacts_are_hashed_retained_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            binary = directory / 'linked'
            binary.write_bytes(elf())
            output = io.StringIO()
            tools = {'llvm-nm': Path('/tools/nm'), 'llvm-objdump': Path('/tools/objdump')}
            results = [SimpleNamespace(stdout=text, stderr='') for text in ('symbols', 'assembly', 'execution')]
            with patch.object(native.linked, 'ROOT', directory), patch.object(native.linked, 'symbols', return_value=list(range(11))), \
                    patch.object(native.packaged.archives, 'run', side_effect=results), contextlib.redirect_stdout(output):
                self.assertEqual(native.observe(binary, directory, {}, tools, directory), 'execution')
            artifacts = [json.loads(line) for line in output.getvalue().splitlines() if line.startswith('{')]
            self.assertEqual(len(artifacts), 3)
            for artifact in artifacts:
                self.assertEqual(hashlib.sha256((directory / artifact['artifact']).read_bytes()).hexdigest(), artifact['sha256'])
            with patch.object(native.linked, 'symbols', return_value=list(range(11))), \
                    patch.object(native.packaged.archives, 'run', side_effect=results[:2]), self.assertRaises(FileExistsError):
                native.observe(binary, directory, {}, tools, directory)
            self.assertEqual((directory / 'linked.elf').read_bytes(), elf())

    def test_diagnostic_or_changed_binary_is_not_success_and_artifacts_survive(self):
        for failure in ('diagnostic', 'binary'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                binary = directory / 'linked'
                binary.write_bytes(elf())
                def run(command, *_):
                    if command[0] == str(binary):
                        if failure == 'binary':
                            binary.write_bytes(elf() + b'changed')
                        return SimpleNamespace(stdout='execution', stderr='diagnostic' if failure == 'diagnostic' else '')
                    return SimpleNamespace(stdout='inspection', stderr='')
                with patch.object(native.linked, 'ROOT', directory), \
                        patch.object(native.linked, 'symbols', return_value=list(range(11))), \
                        patch.object(native.packaged.archives, 'run', side_effect=run), \
                        contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                    native.observe(binary, directory, {}, {'llvm-nm': Path('/nm'), 'llvm-objdump': Path('/objdump')}, directory)
                self.assertEqual((directory / 'linked.elf').read_bytes(), elf())

    def test_registry_keeps_native_correctness_separate_from_review(self):
        registry = tomllib.loads((native.linked.ROOT / 'verification/checks.toml').read_text())
        for suffix, compiler in (('msrv', '1.90.0'), ('current', '1.99.1')):
            check = next(c for c in registry['checks'] if c['component'] == 'aes' and c['id'] == 'packaged-arm-native-' + suffix)
            self.assertEqual(check['platform'], 'linux-aarch64')
            self.assertEqual(check['category'], 'native-correctness')
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-aarch64-native.py', '--toolchain', compiler])
            self.assertIn('aes-packaged', check['inputs'])
            self.assertIn('aes-arm-native', check['inputs'])
            self.assertEqual(check['success']['unique_lines'], [
                native.marker(compiler, route, panic) for route in ('direct', 'facade') for panic in ('abort', 'unwind')
            ] + [f'AES ARM native completed: {compiler}; four configurations; correctness only; no timing or machine-code approval'])


if __name__ == '__main__':
    unittest.main()
