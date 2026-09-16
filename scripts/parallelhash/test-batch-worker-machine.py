#!/usr/bin/env python3
"""Machine normal-path cleanup reachability/parser regressions, not ISA proofs."""
import batch_worker_machine as check

SPAWN = '_ZN3std3sys3pal4unix6thread6Thread3new17h1234E'
CLEAR, DROP = '_clear', '_drop'
X86 = '''.cfi_startproc
callq SPAWN
testq %rax, %rax
je .LBB0_1
callq _clear
jmp .LBB0_2
.LBB0_1:
callq _drop
.LBB0_2:
retq
.cfi_endproc'''.replace('SPAWN', SPAWN)
ARM = '''.cfi_startproc
bl SPAWN
cbz x0, .LBB0_1
bl _clear
b .LBB0_2
.LBB0_1:
bl _drop
.LBB0_2:
ret
.cfi_endproc'''.replace('SPAWN', SPAWN)


def rejects(body, arm=False, apple=False):
    try:
        check.inspect(body, CLEAR, DROP, {'_abort'}, arm, apple)
    except ValueError:
        return
    raise AssertionError('machine cleanup regression survived:\n' + body)


def main():
    count = 0
    for body, arm, apple in ((X86, False, False), (ARM, True, False),
                             (ARM.replace('bl _', 'bl __'), True, True)):
        check.inspect(body, CLEAR, DROP, {'_abort'}, arm, apple)
        call, ret = ('bl', 'ret') if arm else ('callq', 'retq')
        prefix = '_' if apple else ''
        for symbol in (CLEAR, DROP):
            line = call + ' ' + prefix + symbol
            for replacement in ('', line + '_wrong', ret):
                rejects(body.replace(line, replacement), arm, apple)
                count += 1
        for before, after in (
            ('.LBB0_1:', '.LBB0_8:'), ('.LBB0_2:', '.LBB0_8:'),
            ('.LBB0_2:', '.LBB0_1:'),
            ('.cfi_startproc', '.cfi_startproc\n.cfi_startproc'),
            ('.cfi_endproc', ''), ('.LBB0_1:', '.LBB0_1:\n.byte 0xc3'),
            ('.LBB0_1:', '.LBB0_1:\nunknown_op'),
            ('.LBB0_1:', '.LBB0_1:\n#APP' if not arm else '.LBB0_1:\n//APP'),
            (SPAWN, SPAWN + '_wrong'),
        ):
            rejects(body.replace(before, after), arm, apple)
            count += 1
        # An earlier clean path cannot mask a dirty path at the shared return.
        rejects(body.replace(call + ' ' + prefix + DROP, call + ' ' + prefix + '_unknown'), arm, apple)
        count += 1
        # Calling unknown functions indirectly cannot count as cleanup.
        rejects(body.replace(call + ' ' + prefix + DROP, 'blr x8' if arm else 'callq *%rax'), arm, apple)
        count += 1
        # ABI-conforming indirect calls returning normally are conservative edges.
        check.inspect(body.replace('.LBB0_1:', '.LBB0_1:\n' + ('blr x8' if arm else 'callq *%rax')),
                      CLEAR, DROP, {'_abort'}, arm, apple)
        # Distinct state across a loop: spawning again invalidates earlier cleanup.
        loop = body.replace('.cfi_startproc', '.cfi_startproc\n.LBB0_3:').replace(
            '.LBB0_2:', '.LBB0_2:\n' + ('cbnz x1, .LBB0_3' if arm else 'jne .LBB0_3'))
        check.inspect(loop, CLEAR, DROP, {'_abort'}, arm, apple)
        rejects(loop.replace(call + ' ' + prefix + DROP, ''), arm, apple)
        count += 1
        # Hidden second instructions and opaque transfers are never data ops.
        for line in (ret + '; ' + ret, 'br x8' if arm else 'jmp *%rax',
                     'b _foreign' if arm else 'jmp _foreign',
                     '.inst 0xd65f03c0' if arm else '.byte 0xc3'):
            rejects(body.replace('.LBB0_1:', '.LBB0_1:\n' + line), arm, apple)
            count += 1
    got = X86.replace('callq ' + SPAWN, 'callq *' + SPAWN + '@GOTPCREL(%rip)')
    check.inspect(got, CLEAR, DROP, {'_abort'}, False, False)
    for branch in check.machine.ARM_BRANCH | {'cbnz', 'tbnz', 'tbz'}:
        replacement = (branch + ' .LBB0_1' if branch in check.machine.ARM_BRANCH else
                       branch + (' x0, #1, .LBB0_1' if branch in ('tbz', 'tbnz') else ' x0, .LBB0_1'))
        check.inspect(ARM.replace('cbz x0, .LBB0_1', replacement), CLEAR, DROP, set(), True, False)
    for branch in check.machine.X86_BRANCH:
        check.inspect(X86.replace('je .LBB0_1', branch + ' .LBB0_1'), CLEAR, DROP, set(), False, False)
    # Stop only at independently identified noreturn calls; they prove no erase.
    extra = X86.replace('testq %rax, %rax', 'testq %rax, %rax\nje .LBB0_4').replace(
        '.cfi_endproc', '.LBB0_4:\ncallq _abort\n.cfi_endproc')
    check.inspect(extra, CLEAR, DROP, {'_abort'}, False, False)
    rejects(extra.replace('callq _abort', 'callq _unknown'))
    count += 1
    # Assembly alone must fail if a cleanup is removed; no LLVM change is made.
    print(f'Machine normal-path cleanup rejects {count} bypass/identity/loop/parser regressions')


if __name__ == '__main__':
    main()
