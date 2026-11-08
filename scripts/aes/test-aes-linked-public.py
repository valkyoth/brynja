#!/usr/bin/env python3
"""Public-release guards, constructor cleanup and exact symbol regressions."""
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


public = module('public', 'aes_linked_public.py')
elf = module('public_elf', 'test-aes-linked-mix.py')


def table(current=False):
    names = []
    for width in (128, 192, 256):
        for kind in ('9public', '16cached_public'):
            names.append(f'_RNvCsABC_6linked{kind}{width}' if current else
                         f'_ZN6linked{kind}{width}17h0000000000000000E')
        for owner in (f'9Aes{width}Key', f'17Aes{width}ExpandedKey'):
            wide = '4wide' if width != 128 else ''
            names.append(f'_RNvMs_Nt' + ('Nt' if wide else '') +
                         f'CsABC_13brynja_crypto3aes{wide}NtB4_{owner}3new' if current else
                         f'_ZN13brynja_crypto3aes{wide}{owner}3new17h0000000000000000E')
    return '\n'.join(f'{0x1000 + i * 256:016x} 0000000000000010 t {name}' for i, name in enumerate(names))


def fixture(role):
    """Real ordinary constructor; minimal non-AES programs for other controls."""
    width = int(role[-3:]) // 8
    targets = {edge: (edge, 0x1100 + i * 16, 1) for i, edge in enumerate(public.EDGES[role])}
    if role.startswith('new'):
        rows = [('4157', 'pushq %r15'), ('4156', 'pushq %r14'), ('53', 'pushq %rbx'),
                ('4889d3', 'movq %rdx, %rbx'), ('4989f6', 'movq %rsi, %r14'),
                ('4989ff', 'movq %rdi, %r15'), ('be' + struct.pack('<I', width).hex(), f'movl ${width}, %esi'),
                ('4889d7', 'movq %rdx, %rdi'), ('call', 'zeroize'),
                ('ba' + struct.pack('<I', width).hex(), f'movl ${width}, %edx'),
                ('4889df', 'movq %rbx, %rdi'), ('4c89f6', 'movq %r14, %rsi'), ('call', 'copy'),
                ('49895f08', 'movq %rbx, 8(%r15)'),
                ('49c74710' + struct.pack('<I', width).hex(), f'movq ${width}, 16(%r15)'),
                ('49c70700000000', 'movq $0, (%r15)'), ('5b', 'popq %rbx'),
                ('415e', 'popq %r14'), ('415f', 'popq %r15'), ('c3', 'retq')]
    elif role.startswith('cached_new'):
        rows = [('55', 'pushq %rbp'), ('be10000000', 'movl $16, %esi'), ('call', 'zeroize'),
                ('call', 'expand' + role[-3:]), ('84c0', 'testb %al, %al'), ('branch', 'je'),
                ('49c70601000000', 'movq $1, (%r14)'), ('ba10000000', 'movl $16, %edx'),
                ('call', 'copy'), ('be10000000', 'movl $16, %esi'), ('call', 'zeroize'),
                ('5d', 'popq %rbp'), ('c3', 'retq')]
    else:
        constructor = ('cached_new' if role.startswith('cached_') else 'new') + role[-3:]
        rows = [('55', 'pushq %rbp'), ('call', constructor), ('call', 'transform' + role[-3:]),
                ('89c5', 'movl %eax, %ebp'), ('84c0', 'testb %al, %al'), ('branch', 'jne'),
                ('0f280424', 'movaps (%rsp), %xmm0'), ('410f1107', 'movups %xmm0, (%r15)'),
                ('be10000000', 'movl $16, %esi'), ('call', 'zeroize'),
                ('be10000000', 'movl $16, %esi'), ('call', 'zeroize'), ('5d', 'popq %rbp'), ('c3', 'retq')]
    sizes = [5 if code == 'call' else 2 if code == 'branch' else len(bytes.fromhex(code)) for code, _ in rows]
    raw, lines = bytearray(), []
    for (code, text), size in zip(rows, sizes):
        if code == 'call':
            target = targets[text][1]
            code = (b'\xe8' + struct.pack('<i', target - 0x1000 - len(raw) - size)).hex()
            text = f'callq 0x{target:x} <{text}>'
        elif code == 'branch':
            dest = sum(sizes) - 1
            code = bytes((0x74 if text == 'je' else 0x75, dest - len(raw) - size)).hex()
            text = f'{text} 0x{0x1000 + dest:x} <boundary+0x{dest:x}>'
        raw.extend(bytes.fromhex(code))
        lines.append(text)
    image = bytearray(elf.fixture()[-1])
    struct.pack_into('<QQ', image, 152, 0x180, 0x180)
    image[0x200:0x200 + len(raw)] = raw
    return [lines, bytes(raw), sizes, 'boundary', 0x1000, bytes(image), targets]


class LinkedPublicTests(unittest.TestCase):
    def test_exact_symbol_population_and_namespaces(self):
        for current in (False, True):
            value = table(current)
            self.assertEqual(set(public.candidates(value)), set(public.EDGES))
            rows = value.splitlines()
            for changed in ('\n'.join(rows[:-1]), value + '\n' + rows[0], value.replace(' t ', ' D '),
                            value.replace('0000000000000010', '0000000000000000'),
                            value.replace('0000000000001100', '0000000000001001'),
                            value.replace('9public128', '9public999'),
                            value.replace('17Aes128ExpandedKey', '17Aes999ExpandedKey'),
                            value.replace('3aes4wide', '3aes'),
                            value + '\n' + rows[0].replace('6linked', '7foreign6linked')):
                with self.subTest(current=current, changed=changed[-100:]), self.assertRaises(ValueError):
                    public.candidates(changed)

    def test_policy_and_exact_width_call_graph(self):
        self.assertEqual(len(public.EDGES), 12)
        self.assertEqual(set(public.EDGES), set(public.POLICY))
        self.assertEqual(len({p['text_sha256'] for p in public.POLICY.values()}), 12)
        for role, edges in public.EDGES.items():
            for edge in edges:
                if edge not in ('zeroize', 'copy'):
                    self.assertTrue(edge.endswith(role[-3:]))
            self.assertEqual(public.POLICY[role]['constant_loads'], 0)

    def test_real_ordinary_constructors_and_ten_mutations(self):
        for width in (128, 192, 256):
            role = f'new{width}'
            for compiler in ('1.90.0', '1.99.1'):
                for panic in ('abort', 'unwind'):
                    self.assertEqual(public.mutations(*fixture(role), role, compiler, panic), 10)

    def test_synthetic_error_and_public_release_negative_controls(self):
        for role in public.EDGES:
            if role.startswith('new'):
                continue
            args = fixture(role)
            with self.assertRaisesRegex(ValueError, 'reviewed public/constructor changed'):
                public.check(*args, role, '1.99.1', 'abort')
            actual, _ = public.image_review.observe(*args)
            with patch.dict(public.POLICY, {role: actual}):
                self.assertEqual(public.mutations(*args, role, '1.99.1', 'abort'), 10)

    def test_configuration_and_target_set_are_closed(self):
        args = fixture('new128')
        for compiler, panic, role in (('stable', 'abort', 'new128'), ('1.99.1', 'other', 'new128'),
                                      ('1.99.1', 'abort', 'new999')):
            with self.assertRaisesRegex(ValueError, 'configuration'):
                public.check(*args, role, compiler, panic)
        with self.assertRaisesRegex(ValueError, 'target population'):
            public.check(*args[:-1], {}, 'new128', '1.99.1', 'abort')
        altered = {**args[-1], 'copy': ('zeroize', 0x1100, 1)}
        with self.assertRaisesRegex(ValueError, 'ambiguous call'):
            public.check(*args[:-1], altered, 'new128', '1.99.1', 'abort')


if __name__ == '__main__':
    unittest.main()
