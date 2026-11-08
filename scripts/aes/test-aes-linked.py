#!/usr/bin/env python3
"""Negative controls for packaged final-linked AES observation."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('aes_linked_tests', Path(__file__).with_name('check-aes-linked.py'))
linked = importlib.util.module_from_spec(spec)
spec.loader.exec_module(linked)


def symbol_table():
    roles = ['10substitute', '3mix', '5field7inverse', '6expand', '7add_key', '9transform',
             '4wide6expand', '4wide6expand', '4wide7add_key', '4wide9transform', '4wide9transform']
    return '\n'.join(f'{4096 + i * 256:016x} 0000000000000010 t '
                     f'_ZN13brynja_crypto3aes8portable{role}17h{i:016x}E'
                     for i, role in enumerate(roles))


def decoded(rows='1000: 30 c0 \txorb\t%al, %al\n1002: c3 \tretq\n'):
    return 'exe: file format elf64-x86-64\n\nDisassembly of section .text:\n\n0000000000001000 <inverse>:\n' + rows


def synthetic_review():
    lines = ['xorb %al, %cl'] * 101 + ['retq']
    raw = b'\x30\xc1' * 101 + b'\xc3'
    digest, count = linked.inverse_review(lines)
    value = json.loads(linked.POLICY.read_text())
    row = {'inverse_sha256': digest, 'instructions': count, 'symbol_bytes': len(raw),
           'inverse_bytes_sha256': hashlib.sha256(raw).hexdigest()}
    value['compilers'] = {c: row.copy() for c in ('1.90.0', '1.99.1')}
    return lines, raw, value


class LinkedTests(unittest.TestCase):
    def test_exact_helper_population_is_required(self):
        table = symbol_table()
        self.assertEqual(len(linked.symbols(table)), 11)
        rows = table.splitlines()
        for changed in ('\n'.join(rows[:-1]), table + '\n' + rows[0],
                        table.replace('10substitute', '11substitute'), table.replace(' t ', ' D '),
                        table.replace('0000000000000010', '0000000000000000'),
                        table.replace('0000000000001100', '0000000000001001')):
            with self.subTest(changed=changed[:80]), self.assertRaises(ValueError):
                linked.symbols(changed)

    def test_v0_mangling_requires_exact_wide_profiles(self):
        table = symbol_table()
        old = table.splitlines()[6].split()[-1]
        new = '_RINvNtNtNtCsABC_13brynja_crypto3aes8portable4wide6expandKj18_Kjd0_Kjc_EB8_'
        self.assertEqual(len(linked.symbols(table.replace(old, new))), 11)
        with self.assertRaisesRegex(ValueError, 'wide helper'):
            linked.symbols(table.replace(old, new.replace('Kjd0_', 'Kjf0_')))

    def test_complete_exact_extent_is_decoded(self):
        lines, raw = linked.decode(decoded(), 'inverse', 0x1000, 3)
        self.assertEqual(lines, ['xorb %al, %al', 'retq'])
        self.assertEqual(raw, bytes.fromhex('30c0c3'))
        self.assertEqual(linked.decode(decoded(), 'inverse', 0x1000, 3, True),
                         (lines, raw, [2, 1]))

    def test_full_byte_column_without_trailing_space_decodes(self):
        rows = '1000: 49 b9 ab aa aa aa aa aa aa aa\tmovabsq\t$-6148914691236517205, %r9\n'
        lines, raw = linked.decode(decoded(rows), 'inverse', 0x1000, 10)
        self.assertEqual(len(raw), 10)
        self.assertEqual(lines, ['movabsq $-6148914691236517205, %r9'])
        with self.assertRaisesRegex(ValueError, 'unrecognized disassembly row'):
            linked.decode(decoded(rows.replace('49 b9', '49b9')), 'inverse', 0x1000, 10)

    def test_clearing_symbol_must_be_exact_and_unique(self):
        name = '_ZN11brynja_core22secret_memory_volatile23zeroize_region_volatile17h0123456789abcdefE'
        row = f'0000000000001000 0000000000000069 t {name}'
        self.assertEqual(linked.clearing_symbol(row), (name, 0x1000, 105))
        for text in ('', row + '\n' + row, row + '.clone', row.replace(' t ', ' D '),
                     row.replace('0000000000000069', '0000000000000000')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                linked.clearing_symbol(text)

    def test_missing_duplicate_noncontiguous_and_out_of_extent_bytes_fail(self):
        for output, size in ((decoded(), 2), (decoded(), 4), (decoded().replace('1002:', '1003:'), 3),
                             (decoded().replace('1002:', '1000:'), 3),
                             (decoded().replace('c3 \tretq\n', ''), 3),
                             (decoded() + '1003: cc \tint3\n', 3),
                             (decoded() + 'garbage\n', 3),
                             (decoded().replace('elf64-x86-64', 'elf64-aarch64'), 3),
                             (decoded().replace('<inverse>', '<other>'), 3),
                             (decoded() + '0000000000001000 <inverse>:\n', 3)):
            with self.subTest(output=output, size=size), self.assertRaises(ValueError):
                linked.decode(output, 'inverse', 0x1000, size)

    def test_inverse_policy_checks_both_instruction_text_and_encoding(self):
        lines, raw, policy = synthetic_review()
        self.assertEqual(linked.reviewed(lines, raw, '1.90.0', policy)['instructions'], 102)
        self.assertEqual(linked.mutations(lines, raw, '1.90.0', policy), 10)
        with self.assertRaisesRegex(ValueError, 'explicit re-review'):
            linked.reviewed(lines, raw[:-1] + b'\xcc', '1.90.0', policy)

    def test_policy_cannot_silently_widen(self):
        lines, raw, policy = synthetic_review()
        for field, value in (('schema', 2), ('target', 'aarch64-unknown-linux-gnu'),
                             ('routes', ['direct']), ('panics', ['abort']),
                             ('profile', 'opt0'), ('review', 'other')):
            changed = copy.deepcopy(policy)
            changed[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'scope changed'):
                linked.reviewed(lines, raw, '1.90.0', changed)
        changed = copy.deepcopy(policy)
        changed['compilers']['1.90.0']['inverse_sha256'] = 'bad'
        with self.assertRaisesRegex(ValueError, 'invalid linked inverse policy'):
            linked.reviewed(lines, raw, '1.90.0', changed)
        with self.assertRaisesRegex(ValueError, 'unreviewed linked compiler'):
            linked.reviewed(lines, raw, 'stable', policy)

    def test_linked_markers_exact_not_just_one_success_string(self):
        output = '\n'.join(linked.KAT_LINES) + '\n'
        linked.output_check(output)
        for changed in (output + output, '\n'.join(linked.KAT_LINES[:-1]),
                        output.replace('256', '192'), output + 'unexpected\n'):
            with self.assertRaises(ValueError):
                linked.output_check(changed)

    def test_profile_and_frozen_consumer_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest = directory / 'Cargo.toml'
            manifest.write_text('[profile.release]\noverflow-checks=true\n')
            linked.prepare(directory)
            self.assertEqual((directory / 'src/bin/linked.rs').read_bytes(), linked.FIXTURE.read_bytes())
            profile = tomllib.loads(manifest.read_text())['profile']['release']
            self.assertEqual(profile, {'overflow-checks': True, 'opt-level': 3, 'lto': 'fat',
                                       'codegen-units': 1, 'strip': False})
            manifest.write_text('[profile.release]\nopt-level=0\n')
            with self.assertRaisesRegex(ValueError, 'profile changed'):
                linked.prepare(directory)

    def test_symlinked_fixture_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture = directory / 'alias.rs'
            fixture.symlink_to(linked.FIXTURE)
            with patch.object(linked, 'FIXTURE', fixture), self.assertRaisesRegex(ValueError, 'symlinked'):
                linked.prepare(directory)

    def test_environment_and_host_rejected_before_build(self):
        with patch.object(linked.platform, 'system', return_value='Linux'), \
                patch.object(linked.platform, 'machine', return_value='x86_64'):
            for name in linked.REJECT:
                with patch.dict('os.environ', {name: 'override'}, clear=True), \
                        patch.object(linked, 'build') as build:
                    with self.assertRaisesRegex(ValueError, 'remove ambient'):
                        linked.check('1.90.0')
                    build.assert_not_called()
        with patch.object(linked.platform, 'machine', return_value='aarch64'), self.assertRaisesRegex(ValueError, 'native'):
            linked.check('1.90.0')

    def test_missing_tools_fail_before_build(self):
        with patch.dict('os.environ', {}, clear=True), patch.object(linked.shutil, 'which', return_value=None), \
                patch.object(linked.platform, 'system', return_value='Linux'), \
                patch.object(linked.platform, 'machine', return_value='x86_64'), \
                self.assertRaisesRegex(ValueError, 'missing llvm-nm'):
            linked.check('1.90.0')

    def test_registry_scope_and_completion_population(self):
        registry = tomllib.loads((linked.ROOT / 'verification/checks.toml').read_text())
        for suffix, compiler in (('msrv', '1.90.0'), ('current', '1.99.1')):
            check = next(c for c in registry['checks'] if c['component'] == 'aes' and c['id'] == 'packaged-linked-' + suffix)
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-linked.py', '--toolchain', compiler])
            self.assertEqual(check['platform'], 'linux-x86_64')
            self.assertEqual(set(check['reject_environment']), set(linked.REJECT))
            self.assertTrue({'aes-packaged', 'aes-linked', 'aes-dataflow', 'hkdf-public-api-modern',
                             'compiler', 'hkdf-msrv'} <= set(check['inputs']))
            self.assertEqual(check['success']['unique_lines'], [linked.marker(compiler, route, panic)
                             for route in ('direct', 'facade') for panic in ('abort', 'unwind')] +
                             [f'AES linked completed: {compiler}; four packaged final executables; eleven portable helpers, six secret wrappers, six public boundaries, six constructors and two core routines reviewed'])
        self.assertEqual({tool['program'] for tool in registry['groups']['aes-linked']['tools']},
                         {'llvm-nm', 'llvm-objdump'})
        self.assertEqual(set(registry['groups']['aes-linked']['paths']), {
            'assurance/aes-linked', 'scripts/aes/check-aes-linked.py', 'scripts/aes/test-aes-linked.py',
            'scripts/aes/linked-inverse-review.json', 'scripts/aes/aes_linked_helpers.py',
            'scripts/aes/test-aes-linked-helpers.py', 'scripts/aes/aes_linked_mix.py',
            'scripts/aes/test-aes-linked-mix.py', 'scripts/aes/aes_linked_substitute.py',
            'scripts/aes/test-aes-linked-substitute.py', 'scripts/aes/aes_linked_rounds.py',
            'scripts/aes/test-aes-linked-rounds.py', 'scripts/aes/aes_linked_wrappers.py',
            'scripts/aes/test-aes-linked-wrappers.py', 'scripts/aes/aes_linked_public.py',
            'scripts/aes/test-aes-linked-public.py', 'docs/assurance/aes-linked-review.md'})


if __name__ == '__main__':
    unittest.main()
