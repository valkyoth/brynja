#!/usr/bin/env python3
"""Reject post-clear deallocation, capacity-branch and returning-ABI regressions."""
import batch_worker_glue_machine as check

CLEAR = '_ZN24brynja_hash_parallel_std9execution5batch6worker7Storage5clear17h1234E'
FREE = '_RNvCs123abc_7___rustc14___rust_dealloc'


def main():
    count = 0
    for arm, apple in ((False, False), (True, False), (True, True)):
        for panic in ('abort', 'unwind'):
            lines = check.template(CLEAR, FREE, arm, apple, panic)
            body = '\n'.join(lines).replace('ZERO', '.LBB1_zero')

            def accepts(source):
                check.inspect(source, CLEAR, FREE, arm, apple, panic)

            def rejects(source):
                nonlocal count
                try:
                    accepts(source)
                except ValueError:
                    count += 1
                else:
                    raise AssertionError('normal glue regression survived:\n' + source)

            accepts(body)
            accepts('.Lfunc_begin1:\n.cfi_startproc\n' + body + '\n.cfi_endproc')
            accepts(body.replace('.LBB1_zero', 'LBB99_other'))
            # The exact normal prefix is closed; later exception tails are not
            # claimed here and are unreachable if the clearing callee returns.
            accepts(body + '\nLtmp9:\nbl _exception_tail')
            for index, line in enumerate(body.splitlines()):
                for replacement in ('', 'ret' if arm else 'retq', 'unknown_op'):
                    if replacement != line:
                        mutated = body.splitlines()
                        mutated[index] = replacement
                        rejects('\n'.join(mutated))
            for before, after in (
                (FREE, FREE + '_wrong'),
                ('.LBB1_zero:', '.LBB1_zero:\n.LBB1_zero:'),
                ('.LBB1_zero:', '.LBB1_absent:'),
                ('.LBB1_zero:', '.LBB1_zero:\n.cfi_endproc'),
                ('.LBB1_zero:', '.LBB1_zero:\n.byte 0'),
                ('#8', '#7'), ('$8, %rsi', '$7, %rsi'),
                ('mov w2, #1', 'mov w2, #2'), ('movl $1, %edx', 'movl $2, %edx'),
                ('mov x0, x19', 'mov x0, x20'), ('movq %rbx, %rdi', 'movq %r15, %rdi'),
                ('cbz x8,', 'cbnz x8,'), ('je .LBB', 'jne .LBB'),
            ):
                if before in body:
                    rejects(body.replace(before, after))
            rejects(body + '\n.cfi_startproc; ret')
    print(f'Normal Storage glue rejects {count} instruction, allocation-ABI and branch regressions')


if __name__ == '__main__':
    main()
