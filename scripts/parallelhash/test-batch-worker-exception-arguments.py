#!/usr/bin/env python3
"""Exception-only owner-address setup; not CFI or backing-buffer provenance."""
from pathlib import Path
import runpy

import batch_worker_exception_arguments as check

FIXTURE = runpy.run_path(str(Path(__file__).with_name('test-batch-worker-unwind.py')))


def fixture(arm, apple):
    body = FIXTURE['fixture'](arm, apple)
    initial = ('mov w19, #1\nstp xzr, x19, [sp, #64]' if arm else
               'movq $0, 64(%rsp)\nmovq $1, 72(%rsp)')
    setup = 'add x0, sp, #64' if arm else 'leaq 64(%rsp), %rdi'
    body = body.replace('Ltmp0:\n', initial + '\nLtmp0:\n')
    body = body.replace('Ltmp2:\n', 'Ltmp2:\n' + setup + '\nLtmp4:\n')
    return body, initial, setup


def inspect(body, arm, apple):
    return check.inspect(body, '_clear', '_drop', {'_Unwind_Resume'}, arm, apple)


def rejects(body, arm, apple, expected):
    try:
        inspect(body, arm, apple)
    except ValueError as error:
        assert expected in str(error), str(error)
        return
    raise AssertionError('exception argument regression survived')


def main():
    count = 0
    for arm, apple in ((False, False), (True, False), (True, True)):
        body, initial, setup = fixture(arm, apple)
        root, sites, _ = inspect(body, arm, apple)
        assert root == 64 and len(sites) == 1
        for injected in (('mov x0, xzr', 'mov w0, w0', 'add x0, x0, #8', 'blr x8') if arm else
                         ('xorl %edi, %edi', 'movl %edi, %edi', 'addq $8, %rdi', 'callq *%rax')):
            changed = body.replace('Ltmp4:\n', 'Ltmp4:\n' + injected + '\n')
            check.unwind.inspect(changed, '_clear', '_drop', {'_Unwind_Resume'}, arm, apple, from_entry=True)
            rejects(changed, arm, apple, 'exception destructor must receive')
            count += 1
        for replacement in ('', setup.replace('64', '72'),
                            'mov x0, x19' if arm else 'movq %rbx, %rdi'):
            rejects(body.replace(setup, replacement), arm, apple, 'exception destructor must receive')
            count += 1
        # Either an exception edge or an ordinary branch can enter after setup.
        branch = 'cbz x8, Ltmp4' if arm else 'jne Ltmp4'
        for changed in (body.replace('Ltmp2-Lfunc_begin0', 'Ltmp4-Lfunc_begin0'),
                        body.replace('Ltmp2:\n', 'Ltmp2:\n' + branch + '\n')):
            check.unwind.inspect(changed, '_clear', '_drop', {'_Unwind_Resume'}, arm, apple, from_entry=True)
            rejects(changed, arm, apple, 'exception destructor must receive')
            count += 1
        shift = 'sub sp, sp, #16' if arm else 'subq $16, %rsp'
        rejects(body.replace('Ltmp2:\n', 'Ltmp2:\n' + shift + '\n'), arm, apple, 'frame remains stable')
        count += 1
        # Independent anchor: wrong or ambiguous empty-owner initialization.
        message = 'independent exception Storage header' if arm else 'empty stack Storage header'
        for changed in (body.replace(initial, initial.replace('#1', '#2') if arm else initial.replace('$1', '$2')),
                        body.replace(initial, initial + '\n' + initial.replace('64', '96').replace('72', '104'))):
            rejects(changed, arm, apple, message)
            count += 1
        jump = 'b Ltmp0' if arm else 'jmp Ltmp0'
        rejects(body.replace(initial, jump + '\n' + initial), arm, apple, 'initialization dominates')
        count += 1
        # Equivalent full-width copies remain accepted.
        indirect_setup = ('add x8, sp, #64\nmov x0, x8' if arm else
                          'leaq 64(%rsp), %rax\nmovq %rax, %rdi')
        inspect(body.replace(setup, indirect_setup), arm, apple)
        if arm:
            # Actual Linux compiler form keeps w19 live across unrelated work.
            split = initial.replace('\nstp', '\nstr x1, [sp, #8]\nlsr x8, x27, #2\ntst x27, #3\nstp')
            inspect(body.replace(initial, split), arm, apple)
            for injected in ('mov x19, xzr', 'mov w19, w8', 'add x19, x19, #1'):
                changed = body.replace(initial, initial.replace('\nstp', '\n' + injected + '\nstp'))
                rejects(changed, arm, apple, message)
                count += 1
    print(f'Worker exception owner-address setup rejects {count} initialization/ABI/edge/frame regressions')


if __name__ == '__main__':
    main()
