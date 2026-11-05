#!/usr/bin/env python3
"""Synthetic negative controls for the bounded AES emitted-dataflow model."""
import importlib.util
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('aes_dataflow', Path(__file__).with_name('check-aes-dataflow.py'))
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)

ARGS = 'ptr %state, i1 %inverse'
LOAD = '  %byte = load i8, ptr %state, align 1\n'


def body(instructions):
    return 'start:\n' + instructions + '  ret void\n'


def assembly(instruction=''):
    return 'inverse:\n.cfi_startproc\n' + ('\txorb %al, %cl\n' * 101) + instruction + '\tretq\n.size inverse, .-inverse\n'


class DataflowTests(unittest.TestCase):
    def check(self, instructions, callees=None):
        return flow.check_body('substitute', ARGS, body(instructions), callees or {})

    def test_secret_data_arithmetic_and_fixed_addresses_are_allowed(self):
        self.check(LOAD + '  %value = xor i8 %byte, 27\n'
                   '  %next = getelementptr inbounds i8, ptr %state, i64 1\n'
                   '  store i8 %value, ptr %next, align 1\n')

    def test_public_direction_can_control_branch(self):
        self.check('  br i1 %inverse, label %left, label %right\n'
                   'left:\n  br label %right\nright:\n')

    def test_loaded_byte_cannot_control_branch(self):
        with self.assertRaisesRegex(ValueError, 'secret-dependent branch'):
            self.check(LOAD + '  %condition = icmp eq i8 %byte, 0\n'
                       '  br i1 %condition, label %done, label %done\ndone:\n')

    def test_public_induction_cycle_but_not_loop_carried_secret(self):
        loop = ('  br label %loop\nloop:\n'
                '  %index = phi i8 [ 0, %start ], [ %next, %loop ]\n'
                '  %next = add i8 %index, 1\n'
                '  %end = icmp eq i8 %next, 16\n'
                '  br i1 %end, label %done, label %loop\ndone:\n')
        self.check(loop)
        with self.assertRaisesRegex(ValueError, 'secret-dependent branch'):
            self.check(LOAD + loop.replace('[ 0, %start ]', '[ %byte, %start ]'))

    def test_select_and_phi_propagate_taint(self):
        for value in ('select i1 %inverse, i8 %byte, i8 0', 'phi i8 [ %byte, %start ]'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'secret-dependent branch'):
                self.check(LOAD + '  %value = ' + value + '\n  %end = icmp eq i8 %value, 0\n'
                           '  br i1 %end, label %done, label %done\ndone:\n')

    def test_secret_pointer_selection_load_store_and_gep_rejected(self):
        prefix = LOAD + '  %condition = icmp eq i8 %byte, 0\n  %pointer = select i1 %condition, ptr %state, ptr null\n'
        for access in ('  %other = load i8, ptr %pointer, align 1\n',
                       '  store i8 0, ptr %pointer, align 1\n',
                       '  %next = getelementptr inbounds i8, ptr %pointer, i64 1\n'):
            with self.subTest(access=access), self.assertRaisesRegex(ValueError, 'secret-dependent .*address'):
                self.check(prefix + access)

    def test_secret_gep_index_rejected(self):
        with self.assertRaisesRegex(ValueError, 'secret-dependent address'):
            self.check('  %index = load i64, ptr %state, align 1\n'
                       '  %next = getelementptr i8, ptr %state, i64 %index\n')

    def test_secret_shift_and_rotate_counts_rejected(self):
        for expr in ('shl i8 1, %byte', 'call i8 @llvm.fshl.i8(i8 1, i8 1, i8 %byte)'):
            with self.subTest(expr=expr), self.assertRaisesRegex(ValueError, 'secret-dependent .*count'):
                self.check(LOAD + '  %value = ' + expr + '\n')

    def test_inverse_result_remains_secret(self):
        with self.assertRaisesRegex(ValueError, 'secret-dependent branch'):
            self.check('  %value = call i8 @inv(i8 0)\n  %end = icmp eq i8 %value, 0\n'
                       '  br i1 %end, label %done, label %done\ndone:\n', {'inv': 'inverse'})

    def test_inverse_argument_is_secret_and_status_returns_are_public(self):
        flow.check_body('inverse', 'i8 %a', 'start:\n  ret i8 %a\n', {})
        with self.assertRaisesRegex(ValueError, 'secret-dependent branch'):
            flow.check_body('inverse', 'i8 %a', 'start:\n  %end = icmp eq i8 %a, 0\n'
                            '  br i1 %end, label %done, label %done\ndone:\n  ret i8 %a\n', {})
        with self.assertRaisesRegex(ValueError, 'secret-dependent status return'):
            flow.check_body('add_key', 'ptr %state, ptr %schedule, i64 %round',
                            'start:\n  %value = load i1, ptr %state, align 1\n  ret i1 %value\n', {})

    def test_helper_and_intrinsic_arguments_must_be_public(self):
        for call in ('call void @mix(ptr %state, i1 %condition)',
                     'call void @llvm.memcpy.p0.p0.i64(ptr %pointer, ptr %state, i64 16, i1 false)'):
            with self.subTest(call=call), self.assertRaisesRegex(ValueError, 'secret-dependent .*arguments'):
                self.check(LOAD + '  %condition = icmp eq i8 %byte, 0\n'
                           '  %pointer = select i1 %condition, ptr %state, ptr null\n  ' + call + '\n', {'mix': 'mix'})

    def test_ignored_clear_result_cannot_be_assumed_public(self):
        clear = '_ZN11brynja_core13secret_memory18clear_owned_region17h0123456789abcdefE'
        call = '  %value = call i8 @' + clear + '(ptr %state, i64 16)\n'
        self.check(call)
        with self.assertRaisesRegex(ValueError, 'secret-dependent branch'):
            self.check(call + '  %end = icmp eq i8 %value, 0\n'
                       '  br i1 %end, label %done, label %done\ndone:\n')

    def test_unknown_instructions_calls_and_undefined_values_fail_closed(self):
        for instruction in ('%value = udiv i8 1, 2', '%value = mul i8 1, 2',
                            '%value = call i8 @unknown()', 'call void %state()',
                            '%value = load i8, ptr @global, align 1',
                            '%value = xor i8 %missing, 0',
                            'switch i8 0, label %start []'):
            with self.subTest(instruction=instruction), self.assertRaises(ValueError):
                self.check('  ' + instruction + '\n')

    def test_duplicate_ssa_and_changed_abi_rejected(self):
        with self.assertRaises(ValueError):
            self.check(LOAD + LOAD)
        with self.assertRaises(ValueError):
            flow.check_body('substitute', 'ptr %state, i8 %inverse', body(''), {})

    def test_public_remainder_and_truncation_but_not_secret_division(self):
        args = 'ptr %key, i64 %length, ptr %schedule'
        for width, prefix in (('64', ''), ('8', '  %small = trunc nuw i64 %length to i8\n')):
            value = '%length' if width == '64' else '%small'
            operation = prefix + f'  %position = urem i{width} {value}, 24\n'
            flow.check_body('expand192', args, body(operation), {})
            secret = '  %loaded = load i64, ptr %key, align 1\n'
            with self.subTest(width=width), self.assertRaisesRegex(ValueError, 'secret-dependent remainder'):
                flow.check_body('expand192', args, body(secret + operation.replace('%length', '%loaded')), {})
        for operation in ('urem i64 %length, 32', 'urem i64 %length, %length',
                          'trunc ptr %key to i8', 'trunc i64 %length to i1'):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                flow.check_body('expand192', args, body('  %bad = ' + operation + '\n'), {})

    def test_switch_control_is_public_and_cases_are_exact_constants(self):
        args = 'ptr %key, i64 %length, ptr %schedule'
        switch = ('  switch i64 %length, label %done [\n'
                  '    i64 0, label %done\n    i64 16, label %done\n  ]\ndone:\n')
        flow.check_body('expand256', args, body(switch), {})
        with self.assertRaisesRegex(ValueError, 'secret-dependent switch'):
            flow.check_body('expand256', args, body('  %loaded = load i64, ptr %key, align 1\n'
                                                   + switch.replace('%length', '%loaded')), {})
        for bad in (switch.replace('i64 16', 'i64 0'), switch.replace('i64 16', 'i64 %length'),
                    switch.replace(']', ''), switch.replace('%length', '%missing')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                flow.check_body('expand256', args, body(bad), {})

    def test_wide_helpers_preserve_taint_for_every_role(self):
        for role in ('expand192', 'expand256', 'transform192', 'transform256', 'wide_add_key'):
            args = ', '.join(kind + ' %arg' + str(i) for i, kind in enumerate(flow.SHAPES[role]))
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'secret-dependent branch'):
                flow.check_body(role, args, body('  %byte = load i8, ptr %arg0, align 1\n'
                    '  %condition = icmp eq i8 %byte, 0\n'
                    '  br i1 %condition, label %done, label %done\ndone:\n'), {})

    def test_every_wide_call_edge_is_required(self):
        selected = {}
        for role, shape in flow.SHAPES.items():
            args = ', '.join(kind + ' %arg' + str(i) for i, kind in enumerate(shape))
            calls = []
            for callee in sorted(flow.EDGES[role]):
                operands = ', '.join(kind + (' null' if kind == 'ptr' else ' 0')
                                     for kind in flow.SHAPES[callee])
                calls.append('  ' + ('%secret = call i8' if callee == 'inverse' else 'call void')
                             + ' @' + callee + '(' + operands + ')\n')
            code = 'start:\n' + ''.join(calls) + ('  ret i8 %arg0\n' if role == 'inverse' else '  ret void\n')
            selected[role] = (role, args, code)
        with patch.object(flow, 'select', return_value=selected):
            flow.check_ir('fixture')
        for role in ('expand192', 'expand256', 'transform192', 'transform256'):
            for callee in flow.EDGES[role]:
                changed = dict(selected)
                name, args, code = changed[role]
                code = ''.join(line for line in code.splitlines(True) if '@' + callee + '(' not in line)
                changed[role] = (name, args, code)
                with self.subTest(role=role, callee=callee), patch.object(flow, 'select', return_value=changed), \
                     self.assertRaisesRegex(ValueError, 'call graph changed'):
                    flow.check_ir('fixture')

    def test_wide_selection_follows_consumers_and_rejects_scope_changes(self):
        prefix = '_RNv13brynja_crypto3aes8portable'
        definitions = {prefix + ('5field' if role == 'inverse' else '') + str(len(role)) + role:
                       ('', '') for role in flow.BASE_ROLES}
        definitions[prefix + '4wide7add_key'] = ('', '')
        for bits, extent in ((192, 208), (256, 240)):
            consumer = f'_RNv13brynja_crypto3aes4wide9Aes{bits}Key20encrypt_block_public'
            calls = []
            for helper in ('expand', 'transform'):
                name = prefix + '4wide' + str(len(helper)) + helper + str(bits)
                definitions[name] = (f'ptr dereferenceable({extent}) %schedule', '')
                calls.append('call void @' + name + '()')
            definitions[consumer] = ('', '\n'.join(calls))
        def select(defs, aliases=None):
            with patch.object(flow.graph, 'definitions_and_aliases', return_value=(defs, aliases or {})):
                return flow.select('target triple = "x86_64-unknown-linux-gnu"')
        self.assertEqual(set(select(definitions)), set(flow.SHAPES))
        for name in definitions:
            broken = dict(definitions)
            del broken[name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                select(broken)
        for bits in (192, 256):
            broken = dict(definitions)
            name = prefix + '4wide6expand' + str(bits)
            broken[name] = ('ptr dereferenceable(176) %schedule', '')
            with self.subTest(width=bits), self.assertRaisesRegex(ValueError, 'schedule ABI'):
                select(broken)
        with self.assertRaisesRegex(ValueError, 'population changed'):
            select({**definitions, prefix + '7unknown': ('', '')})
        with self.assertRaisesRegex(ValueError, 'aliases require review'):
            select(definitions, {prefix + 'alias': 'other'})
        broken = dict(definitions)
        consumer = '_RNv13brynja_crypto3aes4wide9Aes192Key20encrypt_block_public'
        broken[consumer] = ('', broken[consumer][1].replace('expand192', 'expand256'))
        with self.assertRaisesRegex(ValueError, 'schedule ABI'):
            select(broken)

    def test_fixed_stack_inverse_assembly_and_arithmetic_lea_allowed(self):
        self.assertEqual(flow.check_inverse_assembly(assembly('\tpushq %rbx\n\tmovb %al, -8(%rsp)\n'
                          '\tleal (,%rdi,8), %eax\n\tcmovnsl %ecx, %eax\n\tpopq %rbx\n'), 'inverse'), 107)

    def test_inverse_assembly_branches_calls_division_and_memory_tables_rejected(self):
        for instruction in ('jne .Lother', 'jmp .Lother', 'callq other', 'divb %cl',
                            'movb (%rdi), %al', 'movb table(%rip), %al',
                            'movb (%rsp,%rdi), %al', 'movb 0x100, %al',
                            'cmovnsl (%rdi), %eax', 'shlb %cl, %al', '.byte 0x75'):
            with self.subTest(instruction=instruction), self.assertRaises(ValueError):
                flow.check_inverse_assembly(assembly('\t' + instruction + '\n'), 'inverse')

    def test_inverse_assembly_secret_stack_pointer_writes_rejected(self):
        for instruction in ('movq %rdi, %rsp', 'movl %edi, %esp', 'addq %rdi, %rsp',
                            'leal (,%rdi,8), %esp', 'popq %rsp', 'pushq (%rsp)'):
            with self.subTest(instruction=instruction), self.assertRaises(ValueError):
                flow.check_inverse_assembly(assembly('\t' + instruction + '\n'), 'inverse')

    def test_missing_truncated_or_duplicated_assembly_rejected(self):
        for value in ('', assembly().replace('inverse:', 'other:'), assembly() + assembly(),
                      assembly().replace('retq', 'xorb %al, %cl'),
                      'inverse:\n retq\n.size inverse, .-inverse\n'):
            with self.assertRaises(ValueError):
                flow.check_inverse_assembly(value, 'inverse')

    def test_failed_configuration_never_prints_completion(self):
        with patch.object(flow, 'collect', side_effect=ValueError('unsupported compiler output')), \
             patch('sys.argv', ['check-aes-dataflow.py']), patch('builtins.print') as emit, \
             self.assertRaises(ValueError):
            flow.main()
        emit.assert_not_called()

    def test_machine_review_policy_covers_exact_scope(self):
        policy = json.loads(flow.machine.POLICY.read_text())
        self.assertEqual(set(policy['compilers']), {'1.90.0', '1.99.1'})
        self.assertEqual(policy['panics'], ['abort', 'unwind'])
        self.assertTrue(all(set(rows) == flow.machine.ROLES for rows in policy['compilers'].values()))

    def test_machine_canonicalization_preserves_cfg_operands_and_alignment(self):
        asm = 'helper:\n.cfi_startproc\n movb 4(%rdi), %al # comment\n je .LBB9_2\n.p2align 4\n.LBB9_2:\n retq\n.size helper, .-helper\n'
        expected = 'movb 4(%rdi), %al\nje @block0\n.p2align 4\n@block0:\nretq\n'
        canonical = flow.machine.canonical_body
        self.assertEqual(canonical(asm, 'helper', {'helper': 'mix'}), expected)
        self.assertEqual(canonical(asm.replace('.LBB9_2', '.LBB123_7').replace('# comment', '# another'),
                                   'helper', {'helper': 'mix'}), expected)
        for original, replacement in (('4(%rdi)', '5(%rdi)'), ('%rdi', '%rax'), ('je ', 'jne '),
                                      ('.p2align 4', '.p2align 5'), ('retq', 'nop\n retq')):
            with self.subTest(replacement=replacement):
                self.assertNotEqual(canonical(asm.replace(original, replacement), 'helper', {'helper': 'mix'}), expected)

    def test_machine_unknown_and_duplicate_symbols_rejected(self):
        for asm in ('helper:\n jmp .Lunknown\n.size helper, .-helper\n',
                    'helper:\n callq _ZN7unknownE\n.size helper, .-helper\n',
                    'helper:\n.Llabel:\n.Llabel:\n retq\n.size helper, .-helper\n',
                    assembly(), ''):
            with self.subTest(asm=asm), self.assertRaises(ValueError):
                flow.machine.canonical_body(asm, 'helper', {'helper': 'mix'})

    def test_machine_callee_identity_is_not_erased(self):
        asm = 'helper:\n callq inverse\n retq\n.size helper, .-helper\n'
        symbols = {'helper': 'mix', 'inverse': 'inverse', 'substitute': 'substitute'}
        first = flow.machine.canonical_body(asm, 'helper', symbols)
        self.assertIn('callq @aes.inverse', first)
        self.assertNotEqual(first, flow.machine.canonical_body(asm.replace('callq inverse', 'callq substitute'), 'helper', symbols))
        # A suffix lookalike cannot normalize to the original callee.
        self.assertNotEqual(first, flow.machine.canonical_body(asm.replace('callq inverse', 'callq inverse_extra'), 'helper', symbols))

    def test_machine_fingerprints_reject_each_changed_helper(self):
        selected = {role: (role, '', '') for role in flow.machine.ROLES}
        asm = ''.join(role + ':\n movb $1, %al\n retq\n.size ' + role + ', .-' + role + '\n' for role in sorted(selected))
        hashes = flow.machine.fingerprints(asm, selected)
        policy = json.loads(flow.machine.POLICY.read_text())
        policy['compilers'] = {compiler: hashes for compiler in policy['compilers']}
        for compiler in policy['compilers']:
            for panic in policy['panics']:
                self.assertEqual(flow.machine.check(asm, selected, compiler, panic, policy), hashes)
        for role in selected:
            changed = asm.replace(role + ':\n movb $1', role + ':\n movb $2')
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'explicit re-review required'):
                flow.machine.check(changed, selected, '1.99.1', 'abort', policy)

    def test_machine_incomplete_policy_and_configuration_rejected(self):
        original = json.loads(flow.machine.POLICY.read_text())
        for field in original:
            policy = copy.deepcopy(original)
            del policy[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                flow.machine.check('', {}, '1.99.1', 'abort', policy)
        for compiler, panic in (('1.98.0', 'abort'), ('1.99.1', 'unknown')):
            with self.assertRaises(ValueError):
                flow.machine.check('', {}, compiler, panic, original)
        for bad in ({}, {'mix': '0' * 64}, {name: 'invalid' for name in flow.machine.ROLES}):
            policy = copy.deepcopy(original)
            policy['compilers']['1.90.0'] = bad
            with self.assertRaises(ValueError):
                flow.machine.check('', {}, '1.99.1', 'abort', policy)

    def test_machine_missing_or_duplicate_helper_rejected(self):
        for selected in ({}, {role: ('same', '', '') for role in flow.machine.ROLES}):
            with self.assertRaises(ValueError):
                flow.machine.fingerprints('', selected)


if __name__ == '__main__':
    unittest.main()
