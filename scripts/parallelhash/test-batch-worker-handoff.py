#!/usr/bin/env python3
"""Scoped stack-owner/ABI handoff regressions, not whole-machine provenance."""
import batch_worker_handoff as check

SPAWN = '_ZN3std3sys3pal4unix6thread6Thread3new17h1234E'
CLEAR, DROP = '_clear', '_drop'
X86 = '''.cfi_startproc
subq $96, %rsp
movq $0, 32(%rsp)
movq $1, 40(%rsp)
callq SPAWN
testq %rax, %rax
je .LBB0_1
movq 40(%rsp), %rbx
movq 48(%rsp), %rsi
movq %rbx, %rdi
callq _clear
jmp .LBB0_2
.LBB0_1:
leaq 32(%rsp), %rdi
callq _drop
.LBB0_2:
addq $96, %rsp
retq
.cfi_endproc'''.replace('SPAWN', SPAWN)
ARM = '''.cfi_startproc
sub sp, sp, #96
mov w8, #1
stp xzr, x8, [sp, #32]
bl SPAWN
cbz x0, .LBB0_1
ldp x21, x1, [sp, #40]
mov x0, x21
bl _clear
b .LBB0_2
.LBB0_1:
add x0, sp, #32
bl _drop
.LBB0_2:
add sp, sp, #96
ret
.cfi_endproc'''.replace('SPAWN', SPAWN)


def inspect(body, arm=False, apple=False):
    return check.inspect(body, CLEAR, DROP, set(), arm, apple)


def rejects(body, arm=False, apple=False, message=None):
    try:
        inspect(body, arm, apple)
    except ValueError as error:
        if message:
            assert message in str(error), str(error)
        return
    raise AssertionError('machine handoff regression survived:\n' + body)


def main():
    count = 0
    for arm, original in ((False, X86), (True, ARM)):
        for apple in ((False, True) if arm else (False,)):
            body = original.replace('bl _', 'bl __') if apple else original
            call = 'bl ' if arm else 'callq '
            suffix = '_' if apple else ''
            clear, drop = call + suffix + CLEAR, call + suffix + DROP
            root, sites, _ = inspect(body, arm, apple)
            assert root == 32 and len(sites) == 2
            loads = 'ldp x21, x1, [sp, #40]' if arm else 'movq 40(%rsp), %rbx'
            substitutions = (
                (loads, loads.replace('40', '32')),
                (loads, loads.replace('40', '48')),
                (loads, loads.replace('x21, x1', 'w21, w1') if arm else loads.replace('movq', 'movl')),
                (loads, ''),
                (clear, ('mov w0, w21\n' if arm else 'movl %ebx, %edi\n') + clear),
                (clear, ('mov x1, xzr\n' if arm else 'movq $0, %rsi\n') + clear),
                (clear, ('mov x0, xzr\n' if arm else 'movq $0, %rdi\n') + clear),
                (clear, call + suffix + '_unknown\n' + clear),
                (clear, ('blr x8\n' if arm else 'callq *%rax\n') + clear),
                (drop, ('mov x0, xzr\n' if arm else 'movq $0, %rdi\n') + drop),
                ('add x0, sp, #32' if arm else 'leaq 32(%rsp), %rdi',
                 'add x0, sp, #40' if arm else 'leaq 40(%rsp), %rdi'),
                ('mov w8, #1' if arm else 'movq $1, 40(%rsp)',
                 'mov w8, #2' if arm else 'movq $2, 40(%rsp)'),
                ('stp xzr, x8, [sp, #32]' if arm else 'movq $0, 32(%rsp)', ''),
            )
            for before, after in substitutions:
                assert before in body
                rejects(body.replace(before, after), arm, apple)
                count += 1
            # Frame changes before or inside setup cannot silently shift fields.
            for change in (('add sp, sp, #16', 'stp x8, x9, [sp, #-16]!',
                            'ldp x8, x9, [sp], #16', 'mov sp, x19') if arm else (
                                'subq $8, %rsp', 'pushq %rax', 'popq %rax',
                                'movq %rax, %rsp', 'lock xaddq %rsp, (%rax)')):
                rejects(body.replace(loads, change + '\n' + loads), arm, apple, 'frame remains stable')
                count += 1
            # A post-spawn edge skips the field load; call reachability still passes.
            branch = 'cbnz x0, .LBB0_3' if arm else 'jne .LBB0_3'
            changed = body.replace(loads, branch + '\n' + loads).replace(clear, '.LBB0_3:\n' + clear)
            rejects(changed, arm, apple, 'machine cleanup arguments')
            count += 1
            # Full-width local register copies preserve the loaded identity.
            inspect(body.replace(loads, loads + '\n' + (
                'mov x22, x21\nmov x21, x22' if arm else 'movq %rbx, %r10\nmovq %r10, %rbx')),
                arm, apple)
            # Reassigning an intermediate register invalidates its old identity.
            rejects(body.replace(loads, loads + '\n' + (
                'mov w21, #0' if arm else 'movl $0, %ebx')), arm, apple, 'machine cleanup arguments')
            count += 1
            # Initializer itself must dominate spawn and have no partial entry.
            skip = 'cbnz x0, .LBB0_4' if arm else 'jne .LBB0_4'
            init = 'mov w8, #1' if arm else 'movq $0, 32(%rsp)'
            changed = body.replace(init, skip + '\n' + init).replace(call + suffix + SPAWN,
                '.LBB0_4:\n' + call + suffix + SPAWN)
            rejects(changed, arm, apple)
            count += 1
            # Pre-spawn empty exits do not authorize skipping setup after spawn.
            pre = 'cbnz x0, .LBB0_3' if arm else 'jne .LBB0_3'
            changed = body.replace(call + suffix + SPAWN, pre + '\n' + call + suffix + SPAWN).replace(
                clear, '.LBB0_3:\n' + clear)
            inspect(changed, arm, apple)
    # Independent full-width field loads and harmless non-owner spills.
    inspect(ARM.replace('ldp x21, x1, [sp, #40]',
                        'ldr x21, [sp, #40]\nldr x1, [sp, #48]'), True)
    inspect(X86.replace('movq %rbx, %rdi', 'movq %rax, 64(%rsp)\nmovq %rbx, %rdi'))
    rejects(X86.replace('movq %rbx, %rdi', 'movq %rax, 40(%rsp)\nmovq %rbx, %rdi'))
    count += 1
    print(f'Machine stack-owner handoff rejects {count} field/width/branch/frame/ABI regressions')


if __name__ == '__main__':
    main()
