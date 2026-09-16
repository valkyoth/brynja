"""Exact worker clear-loop forms with an affine induction argument.

Assume the promoted parameters are a valid Vec base and length n. Its Rust
allocation bound gives 0 <= 256*n <= isize::MAX. Empty storage returns directly.
Otherwise the matched loops start at base with 256*n bytes remaining, clear
256 bytes, preserve base+256 across the ABI call, decrement remaining by 256,
and repeat iff nonzero. Induction covers all n slots without sampling n.

This closed recognizer deliberately fixes reviewed register allocation, stack
layout and instruction order. A compiler change requires review, not a broader
regex. It assumes an ABI-conforming non-unwinding clear; it is not a general ISA,
linker, caller-argument, worker-joining or allocation-lifecycle proof.
"""
import re

from batch_cleanup_flow import require
from batch_output_assembly import parse
from batch_output_machine import callee

X86 = '''testq %rsi, %rsi
je DONE
pushq %r15
pushq %r14
pushq %rbx
movq %rsi, %rbx
shlq $8, %rbx
movq CLEAR@GOTPCREL(%rip), %r14
LOOP:
leaq 256(%rdi), %r15
movl $256, %esi
callq *%r14
movq %r15, %rdi
addq $-256, %rbx
jne LOOP
popq %rbx
popq %r14
popq %r15
DONE:
retq'''
LINUX = '''cbz x1, DONE
stp x29, x30, [sp, #-32]!
stp x20, x19, [sp, #16]
mov x29, sp
lsl x19, x1, #8
LOOP:
mov w1, #256
add x20, x0, #256
bl CLEAR
subs x19, x19, #256
mov x0, x20
b.ne LOOP
ldp x20, x19, [sp, #16]
ldp x29, x30, [sp], #32
DONE:
ret'''
APPLE = '''cbz x1, DONE
stp x20, x19, [sp, #-32]!
stp x29, x30, [sp, #16]
add x29, sp, #16
lsl x19, x1, #8
LOOP:
add x20, x0, #256
mov w1, #256
bl CLEAR
mov x0, x20
subs x19, x19, #256
b.ne LOOP
ldp x29, x30, [sp, #16]
ldp x20, x19, [sp], #32
DONE:
ret'''
LINUX_ABORT = LINUX.replace('mov x29, sp\nlsl x19, x1, #8', 'lsl x19, x1, #8\nmov x29, sp')


def function_code(body):
    if '.cfi_' in body:
        return parse(body)
    # Abort builds may omit CFI entirely. The shared extractor stops at the
    # next Rust symbol; retain every instruction before its header directives
    # and reject executable/data directives interposed in that header.
    lines, header = [], False
    for raw in body.splitlines():
        line = raw.strip()
        if re.match(r'\.(?:section|globl)\s', line):
            header = True
        if header:
            require(not line or re.fullmatch(r'\.(?:section|globl|type)\s+[^\n;]+', line) or
                    re.fullmatch(r'\.p2align\s+\d+', line), 'only next-symbol metadata after abort function')
        else:
            lines.append(raw)
    require(header, 'abort function must have a bounded next-symbol header')
    return parse('\n'.join(lines) + '\n.cfi_endproc')


def fixture(template, symbol):
    return '.cfi_startproc\n' + template.replace('LOOP', '.LBB0_2').replace(
        'DONE', '.LBB0_4').replace('CLEAR', symbol) + '\n.cfi_endproc\n'


def check(body):
    code, labels = function_code(body)
    require(code[0] == ('testq', ['%rsi', '%rsi']) or
            (code[0][0] == 'cbz' and len(code[0][1]) == 2 and code[0][1][0] == 'x1'),
            'exact worker length-empty entry test')
    arm = code[0][0] == 'cbz'
    require(len(code) >= 2, 'complete worker function')
    branch = code[0] if arm else code[1]
    require(branch[0] == ('cbz' if arm else 'je') and len(branch[1]) == (2 if arm else 1), 'worker empty branch')
    done = branch[1][-1]
    back = [(op, args) for op, args in code if op == ('b.ne' if arm else 'jne')]
    require(len(back) == 1 and len(back[0][1]) == 1, 'single worker back edge')
    loop = back[0][1][0]
    require(done != loop and set(labels) == {done, loop}, 'exact worker loop/exit labels')
    normalized = []
    for op, arguments in code:
        args = [('.LBB0_4' if a == done else '.LBB0_2' if a == loop else a) for a in arguments]
        if op == 'bl':
            require(len(args) == 1, 'exact direct clear operand')
            callee(args[0])
            args = ['CLEAR']
        elif op == 'movq' and args and args[0].endswith('@GOTPCREL(%rip)'):
            callee(args[0].removesuffix('@GOTPCREL(%rip)'))
            args[0] = 'CLEAR@GOTPCREL(%rip)'
        normalized.append((op, args))
    normalized_labels = {'.LBB0_4': labels[done], '.LBB0_2': labels[loop]}
    expected = [parse(fixture(template, 'CLEAR')) for template in ((LINUX, LINUX_ABORT, APPLE) if arm else (X86,))]
    require((normalized, normalized_labels) in expected, 'complete reviewed worker assembly induction form')
    return 'arm' if arm else 'x86'


def regressions(body):
    """Only altered assembly is passed back to this independent inspector."""
    check(body)
    replacements = (('256', '255'), ('18clear_owned_region', '18ordinary_region'),
                    ('#8', '#7'), ('$8,', '$7,'), ('jne', 'je'), ('b.ne', 'b.eq'),
                    ('cbz', 'cbnz'), ('je\t', 'jne\t'), ('%r15', '%rax'),
                    ('x20', 'x2'), ('#32', '#16'), ('popq', 'pushq'))
    cases = [body.replace(before, after) for before, after in replacements if before in body]
    cases.append(body + '\nunknown_op' if '.cfi_endproc' not in body else
                 body.replace('.cfi_endproc', 'unknown_op\n.cfi_endproc'))
    for changed in cases:
        try:
            check(changed)
        except ValueError:
            continue
        raise AssertionError('worker assembly mutation survived')
    return len(cases)
