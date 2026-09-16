#!/usr/bin/env python3
"""Reject worker-loop counter, pointer, ABI and early-exit machine regressions."""
import batch_worker_cleanup  # Establish the shared cryptography helper path.
import batch_worker_assembly as check

CLEAR = '_ZN11brynja_core13secret_memory18clear_owned_region17h1234abcdE'


def rejects(body):
    try:
        check.check(body)
    except ValueError:
        return
    raise AssertionError('worker assembly regression survived:\n' + body)


def main():
    count = 0
    for template in (check.X86, check.LINUX, check.LINUX_ABORT, check.APPLE):
        source = check.fixture(template, CLEAR)
        check.check(source)
        check.check(source.replace(CLEAR, '_RNvNtCs123abc_11brynja_core13secret_memory18clear_owned_region'))
        if template != check.X86:
            check.check(source.replace(CLEAR, '_' + CLEAR))
            check.check(source.replace('.LBB', 'LBB'))
        check.check(source.replace('.LBB0_2', '.LBB999_42').replace('.LBB0_4', '.LBB999_24'))
        abort = source.replace('.cfi_startproc\n', '').replace('.cfi_endproc', '.globl _RNvNext\n.p2align 2')
        check.check(abort)
        for suffix in ('unknown_op', '.byte 0', '.globl _RNvBad; ret'):
            rejects(abort + suffix)
            count += 1
        rejects(abort.replace('.globl _RNvNext', 'ret'))
        count += 1
        # Change and remove every executable instruction separately. Unknown
        # syntax, including empty operand lists, must fail with ValueError.
        lines = template.splitlines()
        for i, line in enumerate(lines):
            if line.endswith(':'):
                continue
            for replacement in ('', 'unknown_op', line.split()[0]):
                if replacement == line:
                    continue
                mutated = lines[:i] + [replacement] + lines[i+1:]
                rejects(check.fixture('\n'.join(mutated), CLEAR))
                count += 1
        for before, after in (
            ('256', '255'), ('#8', '#7'), ('$8,', '$7,'),
            ('je DONE', 'jne DONE'), ('jne LOOP', 'je LOOP'),
            ('cbz x1', 'cbnz x1'), ('b.ne LOOP', 'b.eq LOOP'),
            ('LOOP:', 'DONE:'), ('LOOP\n', 'DONE\n'),
            ('%r15', '%rax'), ('x20', 'x2'), ('%rbx', '%rcx'), ('x19', 'x3'),
            ('popq %r15', 'popq %r14'), ('#-32', '#-16'),
            ('[sp], #32', '[sp], #16'), ('#16]', '#8]'),
            ('callq *%r14', 'callq *%rdi'), ('bl CLEAR', 'bl unknown_CLEAR'),
            ('movl $256, %esi', 'movl $255, %esi'), ('mov w1, #256', 'mov w1, #255'),
            ('leaq 256(%rdi), %r15', 'leaq 512(%rdi), %r15'),
            ('add x20, x0, #256', 'add x20, x0, #512'),
            ('addq $-256, %rbx', 'addq $-512, %rbx'),
            ('subs x19, x19, #256', 'subs x19, x19, #512'),
        ):
            if before in template:
                rejects(check.fixture(template.replace(before, after), CLEAR))
                count += 1
        rejects(source.replace(CLEAR, 'unknown_' + CLEAR))
        rejects(source.replace('.cfi_endproc', 'unknown_op\n.cfi_endproc'))
        rejects(source.replace('.cfi_endproc', ''))
        count += 3
    print(f'Worker assembly induction forms: PASS; {count} instruction/ABI/stride/branch regressions rejected')


if __name__ == '__main__':
    main()
