#!/usr/bin/env python3
"""LSDA linkage and spawn-exception cleanup regressions, not runtime unwinding."""
import batch_worker_unwind as check

SPAWN = '_ZN3std3sys3pal4unix6thread6Thread3new17h1234E'
TABLE = '''Lexception0:
.byte 255
.byte TYPE
.uleb128 Lttbase0-Lttbaseref0
Lttbaseref0:
.byte 1
.uleb128 Lcst_end0-Lcst_begin0
Lcst_begin0:
.uleb128 Ltmp0-Lfunc_begin0
.uleb128 Ltmp1-Ltmp0
.uleb128 Ltmp2-Lfunc_begin0
.byte 0
Lcst_end0:
.byte 127
.byte 0
.byte 0
.byte 0
.byte 1
.byte 125
.p2align 2, 0x0
WORD 0
Lttbase0:
.byte 0
.p2align 2, 0x0
'''


def fixture(arm, apple):
    call, ret = ('bl', 'ret') if arm else ('callq', 'retq')
    branch = 'cbz x0, LBB0_1' if arm else 'testq %rax, %rax\nje LBB0_1'
    jump = 'b' if arm else 'jmp'
    prefix = '_' if apple else ''
    encoding = '156' if arm and not apple else '155'
    personality = '_rust_eh_personality' if apple else 'DW.ref.rust_eh_personality'
    body = f'''Lfunc_begin0:
.cfi_startproc
.cfi_personality {encoding}, {personality}
.cfi_lsda {16 if apple else 28 if arm else 27}, Lexception0
Ltmp0:
{call} {prefix}{SPAWN}
Ltmp1:
{branch}
{call} {prefix}_clear
{jump} LBB0_2
LBB0_1:
{call} {prefix}_drop
LBB0_2:
{ret}
Ltmp2:
{call} {prefix}_drop
Ltmp3:
{call} {prefix}_Unwind_Resume
Lfunc_end0:
.cfi_endproc
'''
    return body + TABLE.replace('TYPE', encoding).replace('WORD', '.xword' if arm and not apple else '.long')


def inspect(body, arm, apple):
    return check.inspect(body, '_clear', '_drop', {'_Unwind_Resume'}, arm, apple)


def rejects(body, arm, apple, expected=None):
    try:
        inspect(body, arm, apple)
    except ValueError as error:
        if expected:
            assert expected in str(error), str(error)
        return
    raise AssertionError('worker exception regression survived:\n' + body)


def main():
    count = 0
    for arm, apple in ((False, False), (True, False), (True, True)):
        body = fixture(arm, apple)
        inspect(body, arm, apple)
        call, ret, prefix = ('bl' if arm else 'callq'), ('ret' if arm else 'retq'), ('_' if apple else '')
        for replacement in (ret, call + ' ' + prefix + '_omitted'):
            changed = body.replace('Ltmp2:\n' + call + ' ' + prefix + '_drop', 'Ltmp2:\n' + replacement)
            check.machine.inspect(changed, '_clear', '_drop', {'_Unwind_Resume'}, arm, apple)
            rejects(changed, arm, apple, 'machine unwind path escapes')
            count += 1
        for before, after in (
            ('Lexception0:', 'Lexception1:'),
            ('.cfi_lsda ', '.cfi_lsda 9, Lexception1\n.cfi_lsda '),
            ('.cfi_personality ', '.cfi_personality 9, fake\n.cfi_personality '),
            ('.byte 255', '.byte 254'),
            ('.uleb128 Lttbase0-Lttbaseref0', '.uleb128 Lttbase0-Lttbaseref1'),
            ('Lttbaseref0:\n.byte 1', 'Lttbaseref0:\n.byte 3'),
            ('.uleb128 Lcst_end0-Lcst_begin0', '.uleb128 Lcst_end0-Lcst_begin1'),
            ('.uleb128 Ltmp0-Lfunc_begin0', '.uleb128 Ltmp0-Lfunc_begin1'),
            ('.uleb128 Ltmp1-Ltmp0', '.uleb128 Ltmp1-Ltmp1'),
            ('.uleb128 Ltmp1-Ltmp0', '.uleb128 Ltmp0-Ltmp0'),
            ('.uleb128 Ltmp2-Lfunc_begin0', '.uleb128 Ltmp99-Lfunc_begin0'),
            ('.uleb128 Ltmp2-Lfunc_begin0', '.uleb128 Lfunc_end0-Lfunc_begin0'),
            ('.uleb128 Ltmp2-Lfunc_begin0\n.byte 0', '.byte 0\n.byte 5'),
            ('.uleb128 Ltmp2-Lfunc_begin0\n.byte 0', '.byte 0\n.byte 0'),
            ('.uleb128 Ltmp2-Lfunc_begin0\n.byte 0', '.uleb128 Ltmp2-Lfunc_begin0\n.byte 7'),
            ('Lcst_end0:\n.byte 127', 'Lcst_end0:\n.byte 126'),
            ('.byte 125', '.byte 124'),
            ('Lttbase0:', 'Lttbase1:'),
            ('Lfunc_end0:', 'Ltmp99:'),
        ):
            assert before in body
            rejects(body.replace(before, after), arm, apple)
            count += 1
        entry = '.uleb128 Ltmp0-Lfunc_begin0\n.uleb128 Ltmp1-Ltmp0\n.uleb128 Ltmp2-Lfunc_begin0\n.byte 0\n'
        rejects(body.replace(entry, entry + entry), arm, apple, 'ordered nonoverlapping')
        rejects(body.replace(entry, entry + '.byte 0\n'), arm, apple, 'complete nonempty')
        rejects(body.replace('Ltmp2-Lfunc_begin0', 'Ltmp3-Lfunc_begin0'), arm, apple, 'machine unwind path escapes')
        count += 3
        # A later recorded throwing call can bypass the would-be cleanup.
        secondary = body.replace('Ltmp2:\n', 'Ltmp2:\n' + call + ' ' + prefix + '_unknown\nLtmp4:\n').replace(
            'Lcst_end0:\n', '.uleb128 Ltmp2-Lfunc_begin0\n.uleb128 Ltmp4-Ltmp2\n'
            '.uleb128 Ltmp3-Lfunc_begin0\n.byte 0\nLcst_end0:\n')
        rejects(secondary, arm, apple, 'machine unwind path escapes')
        count += 1
        # Action entries are may-edges: catch selection is not assumed to save us.
        inspect(body.replace(entry, entry.replace('.byte 0', '.byte 5')), arm, apple)
        branch = 'cbz x8, Ltmp3' if arm else 'jne Ltmp3'
        rejects(body.replace('Ltmp2:\n', 'Ltmp2:\n' + branch + '\n'), arm, apple, 'machine unwind path escapes')
        count += 1
    print(f'Worker LSDA/spawn cleanup rejects {count} binding/range/action/escape regressions')


if __name__ == '__main__':
    main()
