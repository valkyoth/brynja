#!/usr/bin/env python3
"""Arm argument roots, fixed-point joins, spills and ABI-clobber regressions."""
import batch_worker_arm_arguments as check
import batch_worker_arm_flow as flow

SPAWN = '_ZN3std3sys3pal4unix6thread6Thread3new17h1234E'
GROW = '_RNvMs5_NtCs123_5alloc7raw_vecNtB5_11RawVecInner11finish_growCs456_24brynja_hash_parallel_std'
BASE, COUNT = ('base', 0), ('count', 0)
BODY = '''.cfi_startproc
sub sp, sp, #512
cmp x22, x27
csel x25, x22, x27, lo
cbnz x25, .LBB0_1
mov w19, #1
stp x20, x19, [sp, #64]
b .LBB0_3
.LBB0_1:
add x0, sp, #256
mov x1, xzr
mov w2, #1
mov x3, x25
mov w4, #1
mov w5, #256
bl GROW
ldr w8, [sp, #256]
tbz w8, #0, .LBB0_2
add sp, sp, #512
ret
.LBB0_2:
ldr x19, [sp, #264]
str x19, [sp, #72]
.LBB0_3:
str x25, [sp, #80]
bl SPAWN
cbz x0, .LBB0_4
ldr x19, [sp, #72]
ldr x25, [sp, #80]
mov x0, x19
mov x1, x25
bl _clear
b .LBB0_5
.LBB0_4:
ldr x21, [sp, #72]
ldr x22, [sp, #80]
mov x0, x21
mov x1, x22
bl _clear
.LBB0_5:
add sp, sp, #512
ret
.cfi_endproc'''.replace('GROW', GROW).replace('SPAWN', SPAWN)


def inspect(body, apple=False):
    return check.inspect(body, '_clear', None, set(), True, apple)


def rejects(body, apple=False, message=None):
    try:
        inspect(body, apple)
    except ValueError as error:
        if message:
            assert message in str(error), str(error)
        return
    raise AssertionError('Arm register/spill regression survived:\n' + body)


def main():
    count = 0
    for apple in (False, True):
        body = BODY.replace('bl _', 'bl __') if apple else BODY
        inspect(body, apple)
        changes = (
            ('mov w5, #256', 'mov w5, #128'),
            ('mov w4, #1', 'mov w4, #8'),
            ('mov w2, #1', 'mov w2, #8'),
            ('mov x1, xzr', 'mov x1, x19'),
            ('mov x3, x25', 'mov x3, x22'),
            ('csel x25, x22, x27, lo', 'csel x25, x22, x27, hi'),
            ('cmp x22, x27', 'cmp w22, w27'),
            ('mov w19, #1', 'mov w19, #0'),
            ('cbnz x25, .LBB0_1', 'cbz x25, .LBB0_1'),
            ('tbz w8, #0', 'tbnz w8, #0'),
            ('ldr x19, [sp, #264]', 'ldr x19, [sp, #272]'),
            ('ldr x19, [sp, #264]', 'ldr w19, [sp, #264]'),
            ('str x19, [sp, #72]', 'str w19, [sp, #72]'),
            ('str x25, [sp, #80]', 'str w25, [sp, #80]'),
            ('ldr x21, [sp, #72]', 'ldr x21, [sp, #80]'),
            ('ldr x22, [sp, #80]', 'ldr x22, [sp, #72]'),
            ('mov x0, x21', 'mov w0, w21'),
            ('mov x1, x22', 'mov w1, w22'),
            ('mov x0, x21', 'add x0, x21, #256'),
            ('mov x1, x22', 'sub x1, x22, #1'),
            ('str x25, [sp, #80]', 'str x25, [sp, #80]\nstrb wzr, [sp, #83]'),
            ('str x25, [sp, #80]', 'str x25, [sp, #80]\nstr q0, [sp, #72]'),
        )
        for before, after in changes:
            rejects(body.replace(before, after), apple)
            count += 1
        suffix = '_' if apple else ''
        clear = 'bl ' + suffix + '_clear'
        for instruction in ('mov x0, xzr', 'mov x1, xzr', 'blr x8', 'bl ' + suffix + '_unknown'):
            rejects(body.replace(clear, instruction + '\n' + clear), apple, 'machine cleanup must receive')
            count += 1
        # Full-width aliases preserve provenance, including stack aliases.
        inspect(body.replace('str x25, [sp, #80]',
                            'mov x26, x25\nadd x9, sp, #80\nstr x26, [x9]'), apple)
        alias = body.replace('str x25, [sp, #80]',
                             'str x25, [sp, #80]\nadd x9, sp, #80\nstr wzr, [x9]')
        rejects(alias, apple, 'machine cleanup must receive')
        count += 1
        # All incoming paths must agree; a correct path cannot hide a bad one.
        fork = body.replace('mov x0, x21', 'cbz x7, .LBB0_6\nmov x21, xzr\n.LBB0_6:\nmov x0, x21')
        rejects(fork, apple, 'machine cleanup must receive')
        count += 1
        loop = body.replace('ldr x21, [sp, #72]', '.LBB0_7:\nldr x21, [sp, #72]').replace(
            'mov x0, x21', 'cbz x7, .LBB0_8\nstr xzr, [sp, #72]\nb .LBB0_7\n.LBB0_8:\nmov x0, x21')
        rejects(loop, apple, 'machine cleanup must receive')
        count += 1
        # Loading both ABI operands before an ordinary call is not sufficient.
        inspect(body.replace('ldr x21, [sp, #72]', 'bl ' + suffix + '_unknown\nldr x21, [sp, #72]'), apple)
        # A branch cannot reuse the flags from an unrelated comparison.
        fork = body.replace('cmp x22, x27', 'cbz x8, .LBB0_9\ncmp x22, x27').replace(
            'csel x25, x22, x27, lo', '.LBB0_9:\ncsel x25, x22, x27, lo')
        rejects(fork, apple, 'immediately preceding comparison')
        count += 1
        for changed in (
            body.replace('cmp x22, x27', 'cbz x9, .LBB0_3\ncmp x22, x27'),
            body.replace('.LBB0_1:', '.LBB0_1:\ncbz x9, .LBB0_3'),
            body.replace('cmp x22, x27', 'cbz x9, .LBB0_6\ncmp x22, x27').replace(
                'mov w19, #1', '.LBB0_6:\nmov w19, #1'),
        ):
            rejects(changed, apple)
            count += 1
    # Small instruction semantics: paired loads use an unchanged memory snapshot,
    # overlapping writes kill every intersecting field, calls preserve x19..x28.
    facts = {64: BASE, 72: COUNT, 'x19': BASE, 'x25': COUNT, 'x0': BASE, 'x1': COUNT}
    assert flow.step('ldp', ['x0', 'x1', '[sp, #64]'], facts)['x1'] == COUNT
    called = flow.step('bl', ['_unknown'], facts)
    assert 'x0' not in called and 'x1' not in called and called['x19'] == BASE and called['x25'] == COUNT
    for op, args in (
        ('str', ['wzr', '[sp, #68]']), ('sturh', ['wzr', '[sp, #70]']),
        ('str', ['q0', '[sp, #64]']), ('casa', ['x19', 'x25', '[sp, #64]']),
        ('ldadd', ['x19', 'x25', '[sp, #64]']),
    ):
        assert 64 not in flow.step(op, args, facts)
        count += 1
    for op, args in (('ldr', ['w0', '[sp, #64]']), ('ldrb', ['w0', '[sp, #64]']),
                     ('ldp', ['w0', 'w1', '[sp, #64]']), ('movk', ['x0', '#1'])):
        assert 'x0' not in flow.step(op, args, facts)
        count += 1
    # Address calculation precedes atomic read/write register clobbers, including
    # when the address register is also the comparison or result operand.
    for op in ('casa', 'ldadd'):
        assert 64 not in flow.step(op, ['x19', 'x25', '[x19]'], dict(facts, x19=('stack', 64)))
        count += 1
    print(f'Arm machine arguments reject {count} root/spill/clobber/merge/loop regressions')


if __name__ == '__main__':
    main()
