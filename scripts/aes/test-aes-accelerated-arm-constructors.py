#!/usr/bin/env python3
"""Fail-closed ARM constructor controls, not synthetic build approval."""
import importlib.util
from pathlib import Path
import re
import tomllib
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


r = module('arm_constructor_tests', 'aes_accelerated_linked_arm_constructors.py')
prior = module('arm_constructor_kernel_fixture', 'test-aes-accelerated-linked.py')
expansion_fixture = module('arm_constructor_expansion_fixture', 'test-aes-accelerated-expansion.py')
runner = prior.runner


def synthetic(cached, unwind=False):
    _, _, original, _ = prior.fixture(r.TARGET)
    image = bytearray(original)
    targets = {'zeroize': ('clear', 0x1600, 4), 'copy': ('copy', 0x1620, 4)}
    if cached:
        targets['expand'] = ('expand', 0x1640, 4)
        if unwind:
            targets['resume'] = ('_Unwind_Resume', 0x1680, 4)
    start = 0x1500
    lines, raw = [], bytearray()
    for name, address, _ in targets.values():
        offset = address - (start + len(raw))
        raw.extend((0x94000000 | ((offset // 4) & 0x3ffffff)).to_bytes(4, 'little'))
        lines.append(f'bl 0x{address:x} <{name}>')
    delta = targets['zeroize'][1] - (start + len(raw))
    raw.extend((0x14000000 | ((delta // 4) & 0x3ffffff)).to_bytes(4, 'little'))
    lines.append('b 0x1600 <clear>')
    image[0x500:0x500 + len(raw)] = raw
    return lines, bytes(raw), ('constructor', start, len(raw)), bytes(image), targets


def symbol_fixture(current):
    # Real expansion templates, deliberately synthetic constructor code.
    names = {}
    for kind, suffix in (('raw', '7new_key'), ('cached', '10new_cached')):
        for bits in (128, 192, 256):
            body = f'30brynja_aes_accelerated_fixture9lifecycle6aes{bits}' + suffix
            names[kind + str(bits)] = '_RNvNtNtCs123_' + body if current else '_ZN' + body + '17h0000000000000000E'
    body = '11brynja_core22secret_memory_transfer10copy_bytes'
    names['copy'] = '_RNvNtCs123_' + body if current else '_ZN' + body + '17h0000000000000000E'
    table, assembly, image, _ = expansion_fixture.fixture(r.TARGET, v0=current)
    nm = []
    for i, (role, name) in enumerate(names.items()):
        start = 0x1800 + 0x100*i
        nm.append(f'{start:016x} 0000000000000008 t {name}')
        word, line = 0xd503201f, 'nop'
        assembly += f'{start:016x} <{name}>:\n {start:x}: {word:08x} \t{line}\n {start+4:x}: d65f03c0 \tret\n\n'
    nm.extend(line for line in table.splitlines() if 'aarch64_expand' in line)
    return '\n'.join(nm), assembly, image


class AcceleratedArmConstructorTests(unittest.TestCase):
    def test_exact_policy_population_and_counts(self):
        for compiler in r.cleanup.COMPILERS:
            for panic in ('abort', 'unwind'):
                for admission in ('static', 'hosted'):
                    entries = [r.policy(kind, bits, compiler, panic, admission)
                               for kind in ('raw', 'cached') for bits in (128, 192, 256)]
                    expected = 2220 if admission == 'static' else 2445 if compiler == '1.90.0' else 2310
                    if (compiler, panic) == ('1.90.0', 'unwind'):
                        expected += 510
                    self.assertEqual(sum(p['instructions'] * 5 for p in entries) + 105, expected)
                    self.assertEqual([p['calls'] for p in entries], [2]*3 +
                                     [12 if (compiler, panic) == ('1.90.0', 'unwind') else 6]*3)
                    self.assertEqual([p['tail_calls'] for p in entries], [1]*3 + [0]*3)
                    for p in entries:
                        self.assertRegex(p['text_sha256'], r'^[0-9a-f]{64}$')
                        self.assertRegex(p['encoding_sha256'], r'^[0-9a-f]{64}$')

    def test_synthetic_constructor_never_passes_production_policy(self):
        for cached in (False, True):
            for compiler in r.cleanup.COMPILERS:
                for panic in ('abort', 'unwind'):
                    args = synthetic(cached, (compiler, panic) == ('1.90.0', 'unwind'))
                    for admission in ('static', 'hosted'):
                        for bits in (128, 192, 256):
                            with self.assertRaisesRegex(ValueError, 'ARM constructor stream changed'):
                                r.check(*args, 'cached' if cached else 'raw', bits, compiler, panic, admission)

    def test_constructor_instruction_byte_and_target_controls(self):
        for cached in (False, True):
            lines, raw, row, image, targets = args = synthetic(cached)
            actual = r.portable.observe(*args, tail_calls=('zeroize',))[0]
            config = ('cached' if cached else 'raw', 128, '1.99.1', 'abort', 'hosted')
            with patch.object(r, 'policy', return_value=actual):
                self.assertEqual(r.mutations(r.check, *args, *config), len(lines) + len(raw))
                for role, target in targets.items():
                    for changed in ((target[0], target[1]+4, 4), ('wrong', target[1], 4), row):
                        wrong = dict(targets); wrong[role] = changed
                        with self.assertRaises(ValueError):
                            r.check(lines, raw, row, image, wrong, *config)
                with self.assertRaisesRegex(ValueError, 'call population changed'):
                    r.check(lines, raw, row, image, {}, *config)

    def test_unwind_constructor_requires_bound_runtime_and_all_mutations(self):
        args = synthetic(True, True)
        lines, raw, row, image, targets = args
        actual = r.portable.observe(*args, tail_calls=('zeroize',))[0]
        config = 'cached', 128, '1.90.0', 'unwind', 'static'
        with patch.object(r, 'policy', return_value=actual):
            self.assertEqual(r.mutations(r.check, *args, *config), len(lines) + len(raw))
            without = {k: v for k, v in targets.items() if k != 'resume'}
            with self.assertRaisesRegex(ValueError, 'call population changed'):
                r.check(lines, raw, row, image, without, *config)
            with self.assertRaises(ValueError):
                r.check(lines, raw, row, image, {**targets, 'resume': ('wrong', 0x1680, 4)}, *config)
        for compiler, panic in (('1.90.0', 'abort'), ('1.99.1', 'abort'), ('1.99.1', 'unwind')):
            with self.assertRaisesRegex(ValueError, 'call population changed'):
                r.check(*args, 'cached', 128, compiler, panic, 'static')

    def test_unwind_profile_is_not_silently_aliased_to_abort(self):
        for admission in ('static', 'hosted'):
            for bits in (128, 192, 256):
                self.assertNotEqual(r.policy('cached', bits, '1.90.0', 'abort', admission),
                                    r.policy('cached', bits, '1.90.0', 'unwind', admission))
                self.assertEqual(r.policy('cached', bits, '1.99.1', 'abort', admission),
                                 r.policy('cached', bits, '1.99.1', 'unwind', admission))

    def test_copy_stream_independent_bytes_and_per_byte_controls(self):
        # Independent literal transcription of the reviewed 21-instruction
        # transfer loop; no scalar/table fallback or library memcpy is admitted.
        raw = bytes.fromhex('e5031faae60302aadf2000f1e3000054246865f8046825f8a5200091c62000d1df2000f162ffff54c60000b42468653804682538a5040091c60400d186ffffb5e4031faae5031faae6031faaff031febc0035fd6')
        lines = ['mov x5, xzr', 'mov x6, x2', 'cmp x6, #8', 'b.lo 0x1528 <copy+0x28>',
                 'ldr x4, [x1, x5]', 'str x4, [x0, x5]', 'add x5, x5, #8', 'sub x6, x6, #8',
                 'cmp x6, #8', 'b.hs 0x1510 <copy+0x10>', 'cbz x6, 0x1540 <copy+0x40>',
                 'ldrb w4, [x1, x5]', 'strb w4, [x0, x5]', 'add x5, x5, #1', 'sub x6, x6, #1',
                 'cbnz x6, 0x152c <copy+0x2c>', 'mov x4, xzr', 'mov x5, xzr', 'mov x6, xzr', 'cmp xzr, xzr', 'ret']
        _, _, original, _ = prior.fixture(r.TARGET)
        image = bytearray(original); image[0x500:0x554] = raw
        args = (lines, raw, ('copy', 0x1500, 84), bytes(image))
        self.assertEqual(r.mutations(r.check_copy, *args), 105)
        self.assertEqual(r.check_copy(*args), r.COPY)

    def test_selector_requires_exact_names_widths_and_population(self):
        for current in (False, True):
            nm, asm, image = symbol_fixture(current)
            selected = r.candidates(nm, asm, image)
            self.assertEqual(len(selected), 10)
            cases = [nm + '\n' + nm.splitlines()[0], '\n'.join(nm.splitlines()[1:]),
                     nm.replace('7new_key', '7new_bad'), nm.replace('6aes1927new_key', '6aes1287new_key'),
                     nm.replace(' t ', ' D '), nm.replace('0000000000001900', '0000000000001804')]
            for bad in cases:
                self.assertNotEqual(bad, nm)
                with self.assertRaises(ValueError): r.candidates(bad, asm, image)
            # Mangling forms cannot omit the legacy hash or append one to v0.
            name = selected['raw128'][0]
            wrong = name + '17h0000000000000000E' if current else name[:-19]
            with self.assertRaises(ValueError): r.candidates(nm.replace(name, wrong), asm, image)
            # Selector must validate actual expansion bodies, not just mangling.
            row = selected['expand192']
            pos = r.kernels.mapped(image, r.TARGET, row[1], row[2])
            damaged = image[:pos] + bytes([image[pos] ^ 1]) + image[pos+1:]
            with self.assertRaises(ValueError):
                r.candidates(nm, asm, damaged)
            with patch.object(r.expansion, 'check', return_value={'bits': 128}):
                with self.assertRaisesRegex(ValueError, 'duplicate ARM expansion width'):
                    r.candidates(nm, asm, image)

    def test_decoder_preserves_operands_and_rejects_architecture(self):
        nm, asm, image = symbol_fixture(False)
        row = r.candidates(nm, asm, image)['raw128']
        self.assertEqual(r.decode(asm.replace('nop', 'cmp x1, #0x18'), row)[0], ['cmp x1, #24', 'ret'])
        for bad in (asm.replace('elf64-littleaarch64', 'elf64-x86-64'), asm.replace('nop', 'unbound\ntext')):
            with self.assertRaises(ValueError): r.decode(bad, row)

    def test_unknown_configuration_and_missing_dependency_rejected(self):
        for args in (('raw', 512, '1.99.1', 'abort', 'hosted'), ('other', 128, '1.99.1', 'abort', 'hosted'),
                     ('raw', 128, 'other', 'abort', 'hosted'), ('raw', 128, '1.99.1', 'other', 'hosted'),
                     ('raw', 128, '1.99.1', 'abort', 'other')):
            with self.assertRaises(ValueError): r.policy(*args)
        with patch.object(r.cleanup, 'inspect', side_effect=ValueError('cleanup rejected')):
            with patch.object(r, 'candidates') as select:
                with self.assertRaisesRegex(ValueError, 'cleanup rejected'):
                    r.inspect('', '', b'', '1.99.1', 'abort', 'static')
                select.assert_not_called()

    def test_registry_exact_scope_and_dependency_closure(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c.get('category') == 'aes-linked-arm-constructors'}
        self.assertEqual(set(checks), {f'accelerated-arm-constructors-{a}-{e}'
                                     for a in ('static', 'hosted') for e in ('msrv', 'current')})
        for endpoint, tc in (('msrv', '1.90.0'), ('current', '1.99.1')):
            for admission in ('static', 'hosted'):
                check = checks[f'accelerated-arm-constructors-{admission}-{endpoint}']
                self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-accelerated-linked.py',
                    '--toolchain', tc, '--mode', 'arm-qemu', '--admission', admission, '--review-arm-constructors'])
                for group in ('aes-build', 'aes-accelerated-arm-constructors', 'aes-accelerated-arm-cleanup',
                              'aes-accelerated-linked', 'aes-accelerated-campaigns', 'aes-kernel-qemu', 'compiler', 'hkdf-msrv'):
                    self.assertIn(group, check['inputs'])
                self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_ARM_CONSTRUCTORS_LINKED_PASS: {tc} {admission}; four emulated consumers; six constructors, copy, expansion and cleanup closure'])
        paths = registry['groups']['aes-accelerated-arm-constructors']['paths']
        self.assertIn('scripts/aes/aes_aarch64_linked.py', paths)
        self.assertIn('scripts/aes/aarch64-linked-review.json', paths)

    def test_expansion_dependency_cannot_be_skipped(self):
        roles = ['copy', *(kind + str(bits) for kind in ('raw', 'cached', 'expand') for bits in (128, 192, 256))]
        selected = {role: (role, 0x5000 + i * 0x100, 4) for i, role in enumerate(roles)}
        clear = {'zeroize': ('clear', 0x7000, 4)}
        with patch.object(r.cleanup, 'inspect', return_value={}):
            with patch.object(r.cleanup, 'candidates', return_value=clear), patch.object(r, 'candidates', return_value=selected):
                with patch.object(r.kernels, 'select', return_value=[]), patch.object(r, 'decode', return_value=(['ret'], b'\xc0\x03\x5f\xd6')):
                    with patch.object(r.expansion, 'inspect', side_effect=ValueError('expansion rejected')):
                        with patch.object(r, 'check_copy') as copy, patch.object(r, 'check') as constructor:
                            with self.assertRaisesRegex(ValueError, 'expansion rejected'):
                                r.inspect('', '', b'', '1.99.1', 'abort', 'static')
                            copy.assert_not_called()
                            constructor.assert_not_called()

    def test_runner_requires_exclusive_emulated_mode(self):
        cases = [dict(mode='native', admission='static'), dict(mode='arm-qemu', admission='hosted', capture_only=True)]
        for other in ('review_lifecycle', 'review_arm_cleanup', 'review_cached_public', 'review_cached_secret',
                      'review_ephemeral_public', 'review_ephemeral_secret'):
            cases.append(dict(mode='arm-qemu', admission='static', **{other: True}))
        for options in cases:
            with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', review_arm_constructors=True, **options)
            package.assert_not_called()


if __name__ == '__main__':
    unittest.main()
