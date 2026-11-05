#!/usr/bin/env python3
"""Synthetic negative controls; these are not emitted-code evidence."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('wide_operation', Path(__file__).with_name('check-aes-wide-operation-cleanup.py'))
wide = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wide)
CLEAR = '@_RNvNtCsTest_11brynja_core13secret_memory18clear_owned_region'
OWNER_CLEAR = '@_RNvMs0_NtCsTest_11brynja_core13secret_memoryNtB5_17OwnedSecretRegion5clear'
GUARD_DROP = '@_RNvXs_NtCsTest_11brynja_core13secret_memoryNtB4_26SecretRegionInitializationNtNtNtCsTest_4core3ops4drop4Drop4drop'


def fixture(panic):
    text = 'target triple = "x86_64-unknown-linux-gnu"\n'
    for bits, size in wide.WIDTHS.items():
        symbols = {}
        for role, (kind, method) in wide.METHODS.items():
            owner = f'Aes{bits}{kind}'
            symbols[role] = '_ZN13brynja_crypto3aes4wide' + str(len(owner)) + owner + str(len(method)) + method + '17h0123456789abcdefE'
        for role, path in (('expand', '8portable4wide6expand'), ('rounds', '8portable4wide9transform'),
                           ('shared-secret', '4wide6secret')):
            symbols[role] = '_ZN13brynja_crypto3aes' + path + f'17h{bits:016x}E'
        edges = {'encrypt': ('secret',), 'decrypt': ('secret',),
                 'public': ('expand', 'rounds'), 'secret': ('expand', 'shared-secret'),
                 'shared-secret': ('rounds',), 'cached-new': ('expand',),
                 'cached-public': ('rounds',), 'cached-encrypt': ('shared-secret',),
                 'cached-decrypt': ('shared-secret',)}
        for role, symbol in symbols.items():
            args = ''
            body = 'start:\n'
            pointers = {}
            if role in ('expand', 'rounds', 'shared-secret'):
                args = f'ptr noalias dereferenceable({size}) %schedule'
            if role == 'shared-secret':
                args += ', ptr noalias align 8 dereferenceable(24) %destination'
            if role in ('secret', 'cached-new'):
                body += '  %destination = alloca [24 x i8], align 8\n'
            if role in wide.roles(bits):
                pointers = {f'%{name}' + (f'.i{n}' if count > 1 else ''): length
                            for name, (length, count) in wide.roles(bits)[role].items() for n in range(count)}
                for pointer, length in pointers.items():
                    body += f'  {pointer} = alloca [{length} x i8], align 1\n'
                    body += f'  call void @llvm.lifetime.start.p0(ptr {pointer})\n'
                    body += f'  store i8 1, ptr {pointer}, align 1\n'
            unwind = panic == 'unwind' and role in ('public', 'secret', 'shared-secret', 'cached-new', 'cached-public')
            callees = edges.get(role, ())
            for index, callee in enumerate(callees):
                if unwind and index == len(callees) - 1:
                    body += f'  invoke void @{symbols[callee]}()\n    to label %normal unwind label %cleanup\nnormal:\n'
                else:
                    body += f'  call void @{symbols[callee]}()\n'
            if role.endswith('-clear'):
                args = 'ptr %self.0, i64 %self.1'
                body += f'  call void {OWNER_CLEAR}(ptr %self.0, i64 %self.1)\n'
            clears = ''.join(f'  call i8 {CLEAR}(ptr {p}, i64 {s})\n'
                             f'  call void @llvm.lifetime.end.p0(ptr {p})\n' for p, s in pointers.items())
            if role in ('secret', 'cached-new', 'shared-secret'):
                clears += f'  call void {GUARD_DROP}(ptr %destination)\n'
            body += clears + '  ret void\n'
            if unwind:
                body += 'cleanup:\n  %ex = landingpad { ptr, i32 }\n  cleanup\n' + clears + '  resume { ptr, i32 } %ex\n'
            text += f'define void @{symbol}({args}) {{\n{body}}}\n'
    return text


class WideOperationTests(unittest.TestCase):
    def test_all_bodies_and_negative_controls(self):
        for panic in ('abort', 'unwind'):
            selected = wide.check(fixture(panic), panic)
            self.assertEqual({bits: len(rows) for bits, rows in selected.items()}, {192: 13, 256: 13})
            self.assertEqual(wide.negative_controls(selected), 130)

    def test_target_profile_and_named_owners_required(self):
        good = fixture('abort')
        for mutant in (good.replace('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'),
                       good.replace('Aes256Key5clear', 'Aes256Key5other'),
                       good.replace('%previous.i3 = alloca [16 x i8]', '%missing = alloca [16 x i8]')):
            with self.assertRaises(ValueError):
                wide.check(mutant, 'abort')
        for panic in ('unwind', 'unknown'):
            with self.assertRaises(ValueError):
                wide.check(good, panic)

    def test_helper_width_and_edges_required(self):
        good = fixture('abort')
        selected = wide.select(good, 192)
        for role in ('expand', 'rounds', 'shared-secret'):
            symbol, args, _ = selected[role]
            with self.subTest(role=role), self.assertRaises(ValueError):
                wide.check(good.replace(f'@{symbol}({args})', f'@{symbol}({args.replace("208", "240")})'), 'abort')
            with self.subTest(edge=role), self.assertRaises(ValueError):
                wide.check(good.replace(f'call void @{symbol}()', 'call void @unrelated()'), 'abort')

    def test_cached_operations_cannot_expand(self):
        good = fixture('abort')
        selected = wide.select(good, 256)
        for role in ('cached-public', 'cached-encrypt', 'cached-decrypt', 'shared-secret'):
            body = selected[role][2]
            mutant = body.replace('start:', f'start:\n  call void @{selected["expand"][0]}()')
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, 're-expands'):
                wide.check(good.replace(body, mutant), 'abort')

    def test_outline_guard_requires_exact_distinct_argument(self):
        _, args, body = wide.select(fixture('abort'), 192)['shared-secret']
        for changed in (args.replace(', ptr noalias', ', ptr'), args.replace('dereferenceable(24)', 'dereferenceable(16)'),
                        args.replace('%destination', '%unrelated')):
            with self.subTest(args=changed), self.assertRaises(ValueError):
                wide.check_body(changed, body, 192, 'shared-secret')
        for old, new in ((f'{GUARD_DROP}(ptr %destination)', f'{GUARD_DROP}(ptr %state)'),
                         ('start:', 'start:\n  %destination = alloca [24 x i8], align 8'),
                         ('%state)', '%initialization)')):
            with self.subTest(old=old), self.assertRaises(ValueError):
                wide.check_body(args, body.replace(old, new), 192, 'shared-secret')

    def test_default_shared_checker_still_requires_local_guard(self):
        _, _, body = wide.select(fixture('abort'), 192)['shared-secret']
        wide.scratch.SCRATCH['wide-test'] = {'state': 16}
        with self.assertRaisesRegex(ValueError, 'guard storage'):
            wide.scratch.check(body.replace('%destination', '%initialization'), 'wide-test')

    def test_unwind_and_error_paths_cannot_bypass_clearing(self):
        good = fixture('unwind')
        with self.assertRaises(ValueError):
            wide.check(good.replace('cleanup:\n', 'cleanup:\n  resume { ptr, i32 } undef\n'), 'unwind')
        _, args, body = wide.select(fixture('abort'), 192)['public']
        body = body.replace(f'  call i8 {CLEAR}',
                            f'  br i1 %error, label %bad, label %good\nbad:\n  ret void\ngood:\n  call i8 {CLEAR}', 1)
        with self.assertRaises(ValueError):
            wide.check_body(args, body, 192, 'public')


if __name__ == '__main__':
    unittest.main()
