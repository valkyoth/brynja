#!/usr/bin/env python3
"""Ephemeral caller binding controls; synthetic policies never approve a build."""
import importlib.util
from pathlib import Path
import re
import tomllib
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


review = module('ephemeral_review_tests', 'aes_accelerated_linked_ephemeral.py')
kernel_tests = module('ephemeral_kernel_fixture', 'test-aes-accelerated-linked.py')
runner = kernel_tests.runner


def fixture(session_edges=False):
    table, assembly, image, kernels = kernel_tests.fixture(review.TARGET)
    image = bytearray(image)
    clear = ('zeroize', 0x1900, 1)
    copy = ('copy', 0x1920, 1)
    selected, cases = {}, []
    helpers = []
    for bits, start in ((128, 0x1800), (192, 0x1810), (256, 0x1820)):
        name = '_ZN13brynja_crypto3aes8portable' + ('4wide' if bits != 128 else '') + f'6expand17h{bits:016x}E'
        row = (name, start, 5)
        selected[bits] = row
        helpers.append((row, [(f'4883fe{bits // 8:02x}', f'cmpq ${bits // 8}, %rsi'), ('c3', 'retq')]))
    inv = ('_ZN13brynja_crypto3aes8portable5field7inverse17h0000000000000000E', 0x1840, 3)
    helpers += [(inv, [('30c0', 'xorb %al, %al'), ('c3', 'retq')]), (clear, [('c3', 'retq')]), (copy, [('c3', 'retq')])]
    session_targets = {}
    for index, bits in enumerate((128, 192, 256)):
        for offset, direction in enumerate(('encrypt', 'decrypt')):
            row = (f'session_{direction}{bits}', 0x1940 + index * 0x20 + offset * 0x10, 1)
            session_targets[direction, bits] = row
            helpers.append((row, [('c3', 'retq')]))
    for row, instructions in helpers:
        name, start, size = row
        table += f'\n{start:016x} {size:016x} t {name}'
        assembly += f'{start:016x} <{name}>:\n'
        cursor = 0
        for encoded, line in instructions:
            code = bytes.fromhex(encoded)
            assembly += f' {start + cursor:x}: {code.hex(" ")} \t{line}\n'
            image[start - 0x1000 + cursor:start - 0x1000 + cursor + len(code)] = code
            cursor += len(code)
        assembly += '\n'
    for index, bits in enumerate((128, 192, 256)):
        start = 0x1500 + 0x100 * index
        symbol = f'_ZN13brynja_crypto3aes9execution9Aes{bits}Key6secret17h0000000000000000E'
        targets = {'kernel': kernels[index][3], 'expand': selected[bits], 'zeroize': clear, 'copy': copy}
        if session_edges:
            del targets['kernel']
            targets.update({direction: session_targets[direction, bits] for direction in ('encrypt', 'decrypt')})
        lines, raw, sizes = [], bytearray(), []
        instructions = [('be10000000', 'movl $16, %esi'), ('call', 'zeroize'),
                              ('call', 'expand'), ('84c0', 'testb %al, %al'), ('750f', 'jne @+22'),
                              ('call', 'kernel'), ('call', 'copy'), ('call', 'zeroize'), ('c3', 'retq')]
        if session_edges:
            instructions[4:6] = [('7514', 'jne @+27'), ('call', 'encrypt'), ('call', 'decrypt')]
        for encoded, line in instructions:
            if encoded == 'call':
                name, address, _ = targets[line]
                encoded = (b'\xe8' + (address - start - len(raw) - 5).to_bytes(4, 'little', signed=True)).hex()
                line = f'callq 0x{address:x} <{name}>'
            line = re.sub(r'@\+([0-9a-f]+)', lambda m: f'0x{start + int(m[1], 16):x} <{symbol}+0x{m[1]}>', line)
            data = bytes.fromhex(encoded)
            lines.append(line); sizes.append(len(data)); raw.extend(data)
        row = (symbol, start, len(raw))
        table += f'\n{start:016x} {len(raw):016x} t {symbol}'
        image[start - 0x1000:start - 0x1000 + len(raw)] = raw
        cases.append((lines, bytes(raw), sizes, row, targets, bits))
    return table, assembly, bytes(image), cases


class AcceleratedEphemeralTests(unittest.TestCase):
    def test_synthetic_streams_cannot_satisfy_real_policies(self):
        _, _, image, cases = fixture(session_edges=True)
        for lines, raw, sizes, row, targets, bits in cases:
            for tc, panic in review.POLICY:
                with self.assertRaises(ValueError):
                    review.check(lines, raw, sizes, row, image, targets, bits, tc, panic)

    def test_mutations_and_wrong_callees_with_explicit_test_policy(self):
        _, _, image, cases = fixture(session_edges=True)
        policies = {bits: review.image_review.observe(lines, raw, sizes, row[0], row[1], image, targets)[0]
                    for lines, raw, sizes, row, targets, bits in cases}
        with patch.object(review, 'POLICY', {('test', 'abort'): policies}):
            for lines, raw, sizes, row, targets, bits in cases:
                args = (lines, raw, sizes, row, image, targets, bits, 'test', 'abort')
                self.assertEqual(review.mutations(*args), len(lines) + len(raw))
                for role in targets:
                    wrong = dict(targets)
                    other = cases[1 if bits == 128 else 0][4]
                    wrong[role] = other['expand' if role in ('zeroize', 'copy') else role]
                    with self.assertRaises(ValueError):
                        review.check(lines, raw, sizes, row, image, wrong, bits, 'test', 'abort')

    def test_symbol_population_and_mangling_fail_closed(self):
        table, _, _, _ = fixture()
        self.assertEqual(set(review.candidates(table)), {128, 192, 256})
        for changed in ('\n'.join(table.splitlines()[:-1]), table + '\n' + table.splitlines()[-1],
                        table.replace('9Aes128Key6secret', '9Aes999Key6secret'), table.replace(' t ', ' D '),
                        table.replace('0000000000001600', '0000000000001501')):
            with self.assertRaises(ValueError):
                review.candidates(changed)

    def test_expansion_width_is_bound_to_body_not_symbol_hash(self):
        hardware = module('ephemeral_expansion_fixture', 'test-aes-accelerated-expansion.py')
        table, assembly, image, _ = hardware.fixture(review.TARGET)
        result = review.expansion_candidates(table, assembly, image)
        self.assertEqual(set(result), {'expand128', 'expand192', 'expand256'})
        for old, new in (('cmpq $24', 'cmpq $32'), ('cmpq $16', 'cmpq $24'), ('cmpq $32', 'cmpq $0')):
            with self.assertRaises(ValueError):
                review.expansion_candidates(table, assembly.replace(old, new), image)
        for changed in (table.replace('10x86_expand', '10x86_expand_bad'),
                        table + '\n' + next(s for s in table.splitlines() if '6expand' in s),
                        '\n'.join(s for s in table.splitlines() if '6expand' not in s)):
            with self.assertRaises(ValueError):
                review.expansion_candidates(changed, assembly, image)

    def test_real_policy_population_is_exact(self):
        self.assertEqual(set(review.POLICY), {(c, p) for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')})
        expected = {('1.90.0', 'abort'): 1947, ('1.90.0', 'unwind'): 2571,
                    ('1.99.1', 'abort'): 2046, ('1.99.1', 'unwind'): 1938}
        for config, rows in review.POLICY.items():
            self.assertEqual(set(rows), {128, 192, 256})
            self.assertEqual(sum(r['instructions'] + r['symbol_bytes'] for r in rows.values()), expected[config])
            self.assertEqual({r['constant_loads'] for r in rows.values()}, {0})

    def test_required_dependency_reviews_cannot_be_skipped(self):
        with patch.object(review.cached, 'inspect', side_effect=ValueError('cached rejected')):
            with patch.object(review.expansion, 'inspect') as expansion:
                with self.assertRaisesRegex(ValueError, 'cached rejected'):
                    review.inspect('', '', b'', '1.99.1', 'abort')
                expansion.assert_not_called()
        for failing, message in ((review.expansion, 'expansion rejected'), (review.sessions, 'session rejected')):
            with patch.object(review.cached, 'inspect'), patch.object(review.cached, 'candidates', return_value={}), \
                 patch.object(review.expansion, 'inspect'), patch.object(review, 'expansion_candidates'), \
                 patch.object(failing, 'inspect', side_effect=ValueError(message)), patch.object(review, 'candidates') as wrappers:
                with self.assertRaisesRegex(ValueError, message):
                    review.inspect('', '', b'', '1.99.1', 'abort')
                wrappers.assert_not_called()

    def test_review_modes_rejected_before_packaging(self):
        for mode, admission, capture, public, secret in (('arm-qemu', 'static', False, False, False),
                ('arm-qemu', 'hosted', False, False, False), ('native', 'static', True, False, False),
                ('native', 'static', False, True, False), ('native', 'static', False, False, True)):
            with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', mode, admission, capture, public, secret, review_ephemeral_secret=True)
            package.assert_not_called()

    def test_registry_pins_review_and_expansion_dependency_closure(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c.get('category') == 'aes-linked-ephemeral'}
        self.assertTrue({'scripts/aes/aes_accelerated_linked_sessions.py', 'scripts/aes/test-aes-accelerated-sessions.py'}
                        <= set(registry['groups']['aes-accelerated-ephemeral']['paths']))
        self.assertEqual(set(checks), {'accelerated-ephemeral-linked-msrv', 'accelerated-ephemeral-linked-current'})
        for endpoint, tc in (('msrv', '1.90.0'), ('current', '1.99.1')):
            check = checks['accelerated-ephemeral-linked-' + endpoint]
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-accelerated-linked.py',
                '--toolchain', tc, '--mode', 'native', '--admission', 'static', '--review-ephemeral-secret'])
            for group in ('aes-accelerated-ephemeral', 'aes-accelerated-secret', 'aes-accelerated-linked', 'aes-linked', 'aes-dataflow'):
                self.assertIn(group, check['inputs'])
            self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_EPHEMERAL_LINKED_PASS: {tc}; four consumers; x86 cached and ephemeral secret wrappers, expansion closure, kernels, copy and volatile clear'])


if __name__ == '__main__':
    unittest.main()
