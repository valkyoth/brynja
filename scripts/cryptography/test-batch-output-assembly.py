#!/usr/bin/env python3
"""Mutate destructor loops, stack saves, ABI clobbers and exact clear arguments."""
import importlib.util
from pathlib import Path
from unittest.mock import patch

import batch_output_assembly as flow

CLEAR = '_ZN11brynja_core13secret_memory18clear_owned_region17h1234abcdE'
X86 = '''
.cfi_startproc
pushq %r15
pushq %r14
pushq %rbx
xorl %ebx, %ebx
movq CLEAR@GOTPCREL(%rip), %r14
.LBB0_1:
cmpq $32, %rbx
je .LBB0_5
movq (%rdi,%rbx), %rax
addq $16, %rbx
testq %rax, %rax
je .LBB0_1
movq -8(%rdi,%rbx), %rsi
testq %rsi, %rsi
je .LBB0_1
movq %rdi, %r15
movq %rax, %rdi
callq *%r14
movq %r15, %rdi
jmp .LBB0_1
.LBB0_5:
addq $32, %rdi
movl $2, %esi
popq %rbx
movq %r14, %rax
popq %r14
popq %r15
jmpq *%rax
.Lfunc_end0:
.size destructor, .Lfunc_end0-destructor
.cfi_endproc
'''.replace('CLEAR', CLEAR)
ARM = '''
.cfi_startproc
stp x29, x30, [sp, #-48]!
str x21, [sp, #16]
stp x20, x19, [sp, #32]
mov x29, sp
mov x19, x0
mov w20, #32
add x21, x0, #8
b .LBB0_2
.LBB0_1:
add x21, x21, #16
sub x20, x20, #16
.LBB0_2:
cbz x20, .LBB0_6
ldur x0, [x21, #-8]
cbz x0, .LBB0_1
ldr x1, [x21]
cbz x1, .LBB0_1
bl CLEAR
b .LBB0_1
.LBB0_6:
add x0, x19, #32
ldp x20, x19, [sp, #32]
ldr x21, [sp, #16]
mov w1, #2
ldp x29, x30, [sp], #48
b CLEAR
.cfi_endproc
'''.replace('CLEAR', CLEAR)


def rejects(body, arm):
    try:
        flow.check(body, 2, [(32, 2)], arm)
    except ValueError:
        return
    raise AssertionError('invalid assembly accepted:\n' + body)


def check_identity():
    spec = importlib.util.spec_from_file_location('output_driver', Path(__file__).with_name('check-batch-output-codegen.py'))
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    label = '_RNvXs_NtNtCs123abc_16brynja_hash_sha214hardened_batch6output17SecretBatchOutput4Drop4drop'
    glue = label.replace('_RNvXs_', '_RINvNt_').replace('4Drop4drop', '9drop_glue')
    text = glue + ':\n.cfi_startproc\nretq\n.cfi_endproc\n' + label + ':' + X86
    with patch.dict(driver.FAMILIES, {'probe': ('brynja-hash-sha2', 'hardened_batch', 2, [(32, 2)])}):
        assert driver.inspect_assembly({'s': text}, 'probe', 'x86_64-unknown-linux-gnu') == 9
        for bad in (text.replace(label + ':', glue + ':'), text + label + ':' + X86,
                    text.replace('14hardened_batch6output', '17hardened_batch5126output')):
            try:
                driver.inspect_assembly({'s': bad}, 'probe', 'x86_64-unknown-linux-gnu')
            except ValueError:
                pass
            else:
                raise AssertionError('absent, ambiguous or wrong-family Drop identity accepted')


def main():
    check_identity()
    assert flow.check(X86, 2, [(32, 2)], False) == 9
    assert flow.check(ARM, 2, [(32, 2)], True) == 9
    assert flow.check(ARM.replace(CLEAR, '_' + CLEAR), 2, [(32, 2)], True) == 9
    v0 = '_RNvNtCs123abc_11brynja_core13secret_memory18clear_owned_region'
    assert flow.check(X86.replace(CLEAR, v0), 2, [(32, 2)], False) == 9
    mutations = (
        (False, 'xorl %ebx, %ebx', 'movl $16, %ebx'),
        (False, 'cmpq $32', 'cmpq $16'),
        (False, 'cmpq $32', 'cmpq $48'),
        (False, 'addq $16', 'addq $32'),
        (False, 'addq $16', 'addq $0'),
        (False, '(%rdi,%rbx), %rax', '(%rdi), %rax'),
        (False, '-8(%rdi,%rbx)', '(%rdi,%rbx)'),
        (False, 'testq %rax, %rax\nje', 'testq %rax, %rax\njne'),
        (False, 'testq %rsi, %rsi\nje', 'testq %rsi, %rsi\njne'),
        (False, 'movq %rax, %rdi', 'movl $1, %esi'),
        (False, 'movq %rax, %rdi', 'movq %r15, %rdi'),
        (False, 'movq %r15, %rdi', ''),
        (False, 'movq %rdi, %r15', 'movq %rdi, %rdx'),
        (False, 'movq %r15, %rdi', 'movq %rdx, %rdi'),
        (False, 'callq *%r14', 'callq *%r14\ncallq *%r14'),
        (False, 'callq *%r14', 'callq *%rax'),
        (False, 'addq $32, %rdi', 'addq $31, %rdi'),
        (False, 'movl $2, %esi', 'movl $1, %esi'),
        (False, 'popq %r15', 'popq %r14'),
        (False, 'popq %rbx', ''),
        (False, 'movq %r14, %rax', 'movl $0, %eax'),
        (False, 'je .LBB0_5', 'je .LBB0_missing'),
        (False, 'testq %rsi, %rsi', 'testq %rbp, %rbp'),
        (False, 'cmpq $32, %rbx', 'cmpq $32, %rbx\naddq $0, %rbx'),
        (False, 'movq %rax, %rdi', 'movl %eax, %edi'),
        (False, '.LBB0_5:', '.LBB0_1:'),
        (False, '.Lfunc_end0:', '.Lfunc_end0:\nmovl $0, %eax'),
        (True, 'mov w20, #32', 'mov w20, #16'),
        (True, 'mov w20, #32', 'mov w20, #48'),
        (True, 'add x21, x0, #8', 'add x21, x0, #24'),
        (True, 'add x21, x21, #16', 'add x21, x21, #32'),
        (True, 'sub x20, x20, #16', 'sub x20, x20, #0'),
        (True, 'cbz x0', 'cbnz x0'),
        (True, 'cbz x1', 'cbnz x1'),
        (True, '[x21, #-8]', '[x21]'),
        (True, 'ldr x1, [x21]', 'mov w1, #1'),
        (True, 'ldur x0, [x21, #-8]', 'mov x0, x19'),
        (True, 'mov x19, x0', 'mov x2, x0'),
        (True, 'add x0, x19, #32', 'add x0, x2, #32'),
        (True, 'add x0, x19, #32', 'add x0, x19, #31'),
        (True, 'mov w1, #2', 'mov w1, #1'),
        (True, 'ldr x21, [sp, #16]', 'ldr x21, [sp, #24]'),
        (True, '[sp], #48', '[sp], #32'),
        (True, 'stp x20, x19, [sp, #32]', 'stp x20, x19, [x0, #32]'),
        (True, 'ldp x29, x30, [sp], #48', 'ldp x29, x28, [sp], #48'),
        (True, 'cbz x20', 'cbz x22'),
        (True, 'mov x19, x0', 'mov w19, w0'),
    )
    for arm, before, after in mutations:
        source = ARM if arm else X86
        assert before in source
        rejects(source.replace(before, after), arm)
    for arm, source in ((False, X86), (True, ARM)):
        rejects(source.replace(CLEAR, 'unknown_' + CLEAR), arm)
        rejects(source.replace('.cfi_endproc', 'ud2\n.cfi_endproc'), arm)
        rejects(source.replace('.cfi_endproc', ''), arm)
        rejects(source.replace('.cfi_startproc', '.cfi_startproc\nunknown_op'), arm)
    print(f'Batch output assembly: PASS; {len(mutations) + 8} ABI/loop/provenance regressions rejected')
    print('Assembly Drop selection distinguishes glue and rejects three identity regressions')


if __name__ == '__main__':
    main()
