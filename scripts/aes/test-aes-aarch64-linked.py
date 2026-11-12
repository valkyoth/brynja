#!/usr/bin/env python3
"""Negative controls for final-linked ARM instruction/encoding/constant binding."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_linked_tests', Path(__file__).with_name('check-aes-aarch64-linked.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
r = runner.review


def image(raw):
    data = bytearray(0x410)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', data, 16, 3, 183, 1)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HHH', data, 52, 64, 56, 2)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0x200, 0x1000, 0, 0x100, 0x100, 0x1000)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 4, 0x400, 0x2000, 0, 16, 16, 0x1000)
    data[0x200:0x200 + len(raw)] = raw
    data[0x400:] = bytes(range(16))
    return bytes(data)


def words(*values):
    return b''.join(value.to_bytes(4, 'little') for value in values)


def constants():
    lines = ['adrp x8, 0x2000 <pool>', 'ldr d0, [x8, #8]', 'ret']
    raw = words(0xb0000008, 0xfd400500, 0xd65f03c0)
    return lines, raw, ('helper', 0x1000, 12), image(raw), {}


class Aarch64LinkedTests(unittest.TestCase):
    def test_complete_contiguous_disassembly_and_target(self):
        text = 'file format elf64-littleaarch64\n0000000000001000 <helper>:\n 1000: d65f03c0 ret\n'
        row = ('helper', 0x1000, 4)
        self.assertEqual(r.decode(text, row), (['ret'], words(0xd65f03c0)))
        for bad in (text.replace('1000:', '1004:'), text.replace('aarch64', 'x86-64'),
                    text + 'garbage\n', text + text, text.replace('d65f03c0', 'd6'),
                    text + '1004: d503201f nop\n', text.replace('<helper>', '<other>')):
            with self.assertRaises(ValueError): r.decode(bad, row)
        for bad_row in (('helper', 0x1000, 8), ('helper', 0x1001, 4), ('helper', 0x1000, 3)):
            with self.assertRaises(ValueError): r.decode(text, bad_row)

    def test_elf_bounds_architecture_overlap_and_permissions(self):
        good = image(words(0xd65f03c0))
        self.assertEqual(r.mapped(r.segments(good), 0x1000, 4, 5), 0x200)
        for offset, fmt, value in ((18, '<H', 62), (54, '<H', 55), (56, '<H', 0),
                                    (32, '<Q', 99999), (152, '<Q', 99999), (136, '<Q', 0x1080)):
            changed = bytearray(good); struct.pack_into(fmt, changed, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError): r.segments(changed)
        for addr, size, flags in ((0x1100, 4, 5), (0x1000, 4, 4), (0x1000, 0, 5)):
            with self.assertRaises(ValueError): r.mapped(r.segments(good), addr, size, flags)

    def test_constant_page_load_encodings_and_actual_bytes_are_bound(self):
        args = constants()
        actual, positions, text = r.observe(*args)
        self.assertEqual(actual['constants'], 1)
        self.assertEqual(positions, [(0x408, 8)])
        self.assertIn('08090a0b0c0d0e0f', text[1])
        for changed_line in ('adrp x8, 0x3000 <pool>', 'adrp x9, 0x2000 <pool>'):
            with self.assertRaises(ValueError): r.observe([changed_line, *args[0][1:]], *args[1:])
        for changed_line in ('ldr d0, [x8, #16]', 'ldr q0, [x8, #8]', 'ldr d1, [x8, #8]'):
            with self.assertRaises(ValueError): r.observe([args[0][0], changed_line, 'ret'], *args[1:])
        changed = bytearray(args[3]); struct.pack_into('<I', changed, 124, 6)
        with self.assertRaises(ValueError): r.observe(*args[:3], changed, {})

    def test_constant_page_cannot_be_clobbered_or_cross_control(self):
        first, raw, _, _, _ = constants()
        for operation, word in (('mov w8, w0', 0x2a0003e8), ('b 0x100c <helper+0xc>', 0x14000002)):
            code = raw[:4] + words(word) + raw[4:]
            with self.assertRaises(ValueError):
                r.observe([first[0], operation, *first[1:]], code, ('helper', 0x1000, 16), image(code), {})

    def test_local_branch_numeric_annotation_and_encoding_agree(self):
        raw = words(0x54000042, 0xd503201f, 0xd65f03c0)
        row = ('helper', 0x1000, 12)
        text = ['b.hs 0x1008 <helper+0x8>', 'nop', 'ret']
        self.assertEqual(r.observe(text, raw, row, image(raw), {})[0]['branches'], 1)
        for bad in ('b.hs 0x1004 <helper+0x4>', 'b.hs 0x1008 <other+0x8>', 'b.eq 0x1008 <helper+0x8>'):
            with self.assertRaises(ValueError): r.observe([bad, *text[1:]], raw, row, image(raw), {})

    def test_dit_readback_branch_binds_bit_register_and_direction(self):
        row = ('helper', 0x1000, 12)
        for mnemonic, opcode in (('tbz', 0x36000000), ('tbnz', 0x37000000)):
            for bit in (0, 24):
                raw = words(opcode | (bit << 19) | (2 << 5) | 9, 0xd503201f, 0xd65f03c0)
                line = f'{mnemonic} w9, #{bit}, 0x1008 <helper+0x8>'
                self.assertEqual(r.observe([line, 'nop', 'ret'], raw, row, image(raw), {})[0]['branches'], 1)
                for bad in (line.replace(f'#{bit}', f'#{24 if bit == 0 else 0}'),
                            line.replace('w9', 'w8'), line.replace(mnemonic, 'tbnz' if mnemonic == 'tbz' else 'tbz'),
                            line.replace('0x1008 <helper+0x8>', '0x1004 <helper+0x4>'),
                            line.replace(f'#{bit}', '#23')):
                    with self.subTest(bad=bad), self.assertRaises(ValueError):
                        r.observe([bad, 'nop', 'ret'], raw, row, image(raw), {})

    def test_calls_bind_exact_target_and_read_execute_mapping(self):
        raw = words(0x94000008, 0xd65f03c0)
        text, row = ['bl 0x1020 <inverse>', 'ret'], ('helper', 0x1000, 8)
        self.assertEqual(r.observe(text, raw, row, image(raw), {'inverse': ('inverse', 0x1020, 4)})[0]['calls'], 1)
        for targets in ({}, {'inverse': ('wrong', 0x1020, 4)}, {'inverse': ('inverse', 0x1024, 4)}):
            with self.assertRaises(ValueError): r.observe(text, raw, row, image(raw), targets)

    def test_tail_call_requires_explicit_role_and_exact_executable_target(self):
        raw = words(0x14000008)
        row, text = ('helper', 0x1000, 4), ['b 0x1020 <clear>']
        targets = {'zeroize': ('clear', 0x1020, 4)}
        with self.assertRaisesRegex(ValueError, 'unreviewed tail-call target'):
            r.observe(text, raw, row, image(raw), targets)
        actual, _, normalized = r.observe(text, raw, row, image(raw), targets, tail_calls=('zeroize',))
        self.assertEqual((actual['calls'], actual['tail_calls'], normalized), (0, 1, ['b @zeroize']))
        for bad in (('unknown',), ('zeroize', 'zeroize'), ['zeroize']):
            with self.assertRaisesRegex(ValueError, 'invalid tail-call policy'):
                r.observe(text, raw, row, image(raw), targets, tail_calls=bad)
        for wrong in ({'zeroize': ('other', 0x1020, 4)}, {'zeroize': ('clear', 0x1024, 4)},
                      {'zeroize': ('clear', 0x2000, 4)}):
            with self.assertRaises(ValueError):
                r.observe(text, raw, row, image(raw), wrong, tail_calls=('zeroize',))
        for wrong in (words(0x94000008), words(0x14000009)):
            with self.assertRaises(ValueError):
                r.observe(text, wrong, row, image(wrong), targets, tail_calls=('zeroize',))
        # Local B remains local even if tail calls are enabled.
        code = words(0x14000001, 0xd65f03c0)
        result = r.observe(['b 0x1004 <helper+0x4>', 'ret'], code, ('helper', 0x1000, 8),
                           image(code), targets, tail_calls=('zeroize',))[0]
        self.assertEqual((result['branches'], result['tail_calls']), (1, 0))

    def test_compare_test_branches_bind_register_width_predicate_and_bit(self):
        variants = [('b.hi', 0x54000048), ('b.lo', 0x54000043), ('cbz w1,', 0x34000041),
                    ('cbz x1,', 0xb4000041), ('cbnz x9,', 0xb5000049),
                    ('tbz w2, #0,', 0x36000042), ('tbnz w0, #0,', 0x37000040)]
        for op, word in variants:
            raw = words(word, 0xd503201f, 0xd65f03c0)
            text = [op + ' 0x1008 <helper+0x8>', 'nop', 'ret']
            with self.subTest(op=op):
                self.assertEqual(r.observe(text, raw, ('helper', 0x1000, 12), image(raw), {})[0]['branches'], 1)
                # Change the encoded condition/register/width, not just printed text.
                for mask in (1, 1 << 24, 1 << 31):
                    bad = words(word ^ mask, 0xd503201f, 0xd65f03c0)
                    with self.assertRaises(ValueError): r.observe(text, bad, ('helper', 0x1000, 12), image(bad), {})
                if op.startswith('tb'):
                    bad = words(word ^ (1 << 19), 0xd503201f, 0xd65f03c0)
                    with self.assertRaises(ValueError): r.observe(text, bad, ('helper', 0x1000, 12), image(bad), {})

    def test_negative_branch_displacement_stays_inside_symbol(self):
        raw = words(0xd503201f, 0xb5ffffe9, 0xd65f03c0)
        text = ['nop', 'cbnz x9, 0x1000 <helper>', 'ret']
        self.assertEqual(r.observe(text, raw, ('helper', 0x1000, 12), image(raw), {})[0]['branches'], 1)
        text[1] = 'cbnz x9, 0xffc <helper>'
        bad = words(0xd503201f, 0xb5ffffc9, 0xd65f03c0)
        with self.assertRaisesRegex(ValueError, 'extent mismatch'):
            r.observe(text, bad, ('helper', 0x1000, 12), image(bad), {})

    def test_round_width_identity_rejects_mixed_algorithms(self):
        for bits, offset in ((128, 160), (192, 192), (256, 224)):
            wide = '4wide' if bits != 128 else ''
            symbol = '_ZN13brynja_crypto3aes8portable' + wide
            self.assertEqual(r.round_role([f'cmp x1, #{bits // 8}'], symbol + '6expand'), f'expand{bits}')
            loads = [f'ldr q0, [x20, #{offset}]'] * 2
            self.assertEqual(r.round_role(loads, symbol + '9transform'), f'transform{bits}')
            for bad in (loads[:1], loads + loads, [loads[0], 'ldr q0, [x20, #0]']):
                with self.assertRaises(ValueError): r.round_role(bad, symbol + '9transform')
        with self.assertRaises(ValueError): r.round_role(['cmp x1, #16'], '4wide6expand')
        with self.assertRaises(ValueError): r.round_role(['cmp x1, #24'], '_RI4wide6expandKj20_Kjf0_Kje_')

    def test_exact_zeroizer_policy_checks_store_and_loop(self):
        for compiler, code, text in (
            ('1.90.0', words(0xb4000081, 0xf1000421, 0x3800141f, 0x54ffffc1, 0xd65f03c0),
             ['cbz x1, 0x1010 <helper+0x10>', 'subs x1, x1, #1', 'strb wzr, [x0], #1', 'b.ne 0x1004 <helper+0x4>', 'ret']),
            ('1.99.1', words(0xb40000a1, 0xf1000421, 0x3900001f, 0x91000400, 0x54ffffa1, 0xd65f03c0),
             ['cbz x1, 0x1014 <helper+0x14>', 'subs x1, x1, #1', 'strb wzr, [x0]', 'add x0, x0, #1', 'b.ne 0x1004 <helper+0x4>', 'ret'])):
            row = ('helper', 0x1000, len(code))
            r.check(text, code, row, image(code), {}, 'zeroize', compiler)
            for index, replacement in ((1, 'subs x1, x1, #2'), (2, 'nop'), (2, 'strb w1, [x0]')):
                changed = list(text); changed[index] = replacement
                with self.assertRaisesRegex(ValueError, 'policy changed'):
                    r.check(changed, code, row, image(code), {}, 'zeroize', compiler)
            with self.assertRaises(ValueError):
                r.check(text, code, row, image(code), {'inverse': ('bad', 0x1080, 4)}, 'zeroize', compiler)
            with self.assertRaises(ValueError): r.check(text, code, row, image(code), {}, 'zeroize', compiler, panic='unknown')

    def test_symbol_population_and_zeroizer_admission(self):
        tokens = ['5field7inverse', '10substitute', '3mix', '7add_key', '4wide7add_key']
        tokens += ['6expand', '4wide6expand192', '4wide6expand256', '9transform', '4wide9transform192', '4wide9transform256']
        rows = [(token, 0x1000 + i * 0x100, 4) for i, token in enumerate(tokens)]
        zero = '_RNvNtCfixture_11brynja_core22secret_memory_volatile23zeroize_region_volatile'
        nm = '00002000 00000018 t ' + zero
        def decode(_, row):
            bits = 192 if row[0].endswith('192') else 256 if row[0].endswith('256') else 128
            offset = {128: 160, 192: 192, 256: 224}[bits]
            lines = [f'cmp x1, #{bits // 8}'] if 'expand' in row[0] else [f'ldr q0, [x20, #{offset}]'] * 2
            return lines, b''
        with patch.object(r, 'decode', side_effect=decode):
            self.assertEqual(set(r.select(rows, nm, '')), set(r.ROLES))
            for bad_rows, bad_nm in ((rows[:-1], nm), (rows + rows[:1], nm), (rows, ''),
                                     (rows, nm + '\n' + nm), (rows, nm.replace('zeroize', 'other')),
                                     (rows, nm.replace('00002000', '00001000'))):
                with self.assertRaises(ValueError): r.select(bad_rows, bad_nm, '')

    def test_policy_rejects_text_bytes_and_constant_changes(self):
        args = constants()
        policy = json.loads(r.POLICY.read_text())
        policy['compilers']['1.90.0']['inverse'] = r.observe(*args)[0]
        r.check(*args, 'inverse', '1.90.0', policy)
        text = list(args[0]); text[-1] = 'nop'
        changed = bytearray(args[3]); changed[0x408] ^= 1
        for bad in ((text, *args[1:]), (*args[:3], changed, {})):
            with self.assertRaisesRegex(ValueError, 'policy changed'): r.check(*bad, 'inverse', '1.90.0', policy)
        raw = args[1][:-4] + words(0xd503201f)
        changed = bytearray(args[3]); changed[0x200:0x20c] = raw
        with self.assertRaisesRegex(ValueError, 'policy changed'): r.check(args[0], raw, args[2], changed, {}, 'inverse', '1.90.0', policy)
        for key, value in (('schema', 2), ('target', 'x86_64'), ('profile', 'debug'), ('review', 'other')):
            bad = copy.deepcopy(policy); bad[key] = value
            with self.assertRaisesRegex(ValueError, 'scope changed'): r.check(*args, 'inverse', '1.90.0', bad)

    def test_archive_hash_member_types_duplicates_and_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'data.tar'
            for names in (['ok'], ['ok', 'ok'], ['../escape'], ['/absolute']):
                with tarfile.open(path, 'w') as arc:
                    for name in names:
                        member = tarfile.TarInfo(name); member.size = 1
                        arc.addfile(member, io.BytesIO(b'x'))
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if names == ['ok']:
                    self.assertEqual(runner.archive(path, digest), {'ok': b'x'})
                else:
                    with self.assertRaises(ValueError): runner.archive(path, digest)
                with self.assertRaises(ValueError): runner.archive(path, '0' * 64)
            with tarfile.open(path, 'w') as arc:
                member = tarfile.TarInfo('link'); member.type = tarfile.SYMTYPE; member.linkname = 'ok'; arc.addfile(member)
            with self.assertRaises(ValueError): runner.archive(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_configuration_population_and_current_source_fail_closed(self):
        record = json.loads(runner.RECORD.read_text())
        for row in record['native']:
            self.assertEqual(len(runner.configuration_paths(row['artifacts'], row['compiler'])), 8)
            for entries in (row['artifacts'][:-1], row['artifacts'][:-1] + [row['artifacts'][0]]):
                with self.assertRaises(ValueError): runner.configuration_paths(entries, row['compiler'])
        with self.assertRaisesRegex(ValueError, 'retained source differs'): runner.current_sources({})

    def test_registration_is_offline_review_not_native_execution_or_timing(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        check = next(c for c in registry['checks'] if c['component'] == 'aes' and c['id'] == 'aarch64-linked-helpers-review')
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-aarch64-linked.py'])
        self.assertEqual(check['success']['unique_lines'], [runner.MARKER])
        self.assertIn('aes-arm-linked-review', check['inputs'])
        paths = registry['groups']['aes-arm-linked-review']['paths']
        self.assertIn(str(runner.RECORD.relative_to(runner.ROOT)), paths)
        self.assertFalse(any(path.startswith('target/') for path in paths))
        record = json.loads(runner.RECORD.read_text())
        for key, path in (('source_archives', runner.SOURCE), ('observation_archives', runner.ARTIFACTS)):
            rows = [row for row in record[key] if row['path'] == path]
            self.assertEqual(len(rows), 1)
            self.assertRegex(rows[0]['sha256'], r'^[0-9a-f]{64}$')


if __name__ == '__main__': unittest.main()
