#!/usr/bin/env python3
"""Invoke inventory and later-call cleanup regressions on three assembly dialects."""
from pathlib import Path
import runpy

import batch_worker_throwing as check

FIXTURE = runpy.run_path(str(Path(__file__).with_name('test-batch-worker-unwind.py')))
SPAWN = FIXTURE['SPAWN']
LLVM = '''define void @execute() {
start:
  invoke void @SPAWN()
          to label %later unwind label %cleanup
later:
  invoke void @later()
          to label %done unwind label %cleanup
done:
  ret void
cleanup:
  ret void
}'''.replace('SPAWN', SPAWN)


def fixture(arm, apple):
    body = FIXTURE['fixture'](arm, apple)
    call = 'bl' if arm else 'callq'
    prefix = '_' if apple else ''
    body = body.replace('Ltmp1:\n', f'Ltmp1:\nLtmp4:\n{call} {prefix}later\nLtmp5:\n')
    record = ('.uleb128 Ltmp4-Lfunc_begin0\n.uleb128 Ltmp5-Ltmp4\n'
              '.uleb128 Ltmp2-Lfunc_begin0\n.byte 0\n')
    return body.replace('Lcst_end0:\n', record + 'Lcst_end0:\n')


def inspect(llvm, body, arm, apple):
    return check.inspect(llvm, body, '_clear', '_drop', {'_Unwind_Resume'}, arm, apple)


def rejects(llvm, body, arm, apple, expected):
    try:
        inspect(llvm, body, arm, apple)
    except ValueError as error:
        assert expected in str(error), str(error)
        return
    raise AssertionError('throwing-call regression survived')


def main():
    count = 0
    for arm, apple in ((False, False), (True, False), (True, True)):
        body = fixture(arm, apple)
        assert inspect(LLVM, body, arm, apple)[0] == 2
        call, prefix = ('bl' if arm else 'callq'), ('_' if apple else '')
        for llvm, assembly in (
            (LLVM.replace('@later()', '@other()'), body),
            (LLVM, body.replace(f'{call} {prefix}later', f'{call} {prefix}other')),
            (LLVM.replace('invoke void @later()\n          to label %done unwind label %cleanup',
                          'call void @later()\n  br label %done'), body),
            (LLVM.replace('@later()', '%callback()'), body),
            (LLVM, body.replace(f'{call} {prefix}later', 'blr x8' if arm else 'callq *%rax')),
            (LLVM, body.replace(f'{call} {prefix}later', f'{call} {prefix}later\n{call} {prefix}later')),
            (LLVM, body.replace(f'{call} {prefix}later', 'mov x8, x8' if arm else 'movq %rax, %rax')),
        ):
            rejects(llvm, assembly, arm, apple, 'inventory mismatch')
            count += 1
        for ordinal in (0, 1):
            changed = check.unwind.replace_field(body, ordinal, 2, '.byte 0')
            rejects(LLVM, changed, arm, apple, 'inventory mismatch')
            count += 1
        # The old spawn-origin and normal-return checks both accept this mutant.
        changed = check.unwind.replace_field(body, 1, 2, '.uleb128 Ltmp3-Lfunc_begin0')
        check.unwind.inspect(changed, '_clear', '_drop', {'_Unwind_Resume'}, arm, apple)
        rejects(LLVM, changed, arm, apple, 'machine unwind path escapes')
        count += 1
        # Indirect invoke inventory is counted separately, never assigned a
        # fabricated direct identity. Its target provenance remains unproved.
        indirect = body.replace(f'{call} {prefix}later', 'blr x8' if arm else 'callq *%rax')
        assert inspect(LLVM.replace('@later()', '%callback()'), indirect, arm, apple)[0] == 2
        # Noreturn is not nounwind: exceptional edges are visited before
        # ordinary successors stop at the explicitly non-returning call.
        branch = 'cbz x8, Ltmp5' if arm else 'jne Ltmp5'
        changed = changed.replace('Ltmp4:\n', 'Ltmp4:\n' + branch + '\n')
        try:
            check.unwind.inspect(changed, '_clear', '_drop', {'_Unwind_Resume', 'later'},
                                 arm, apple, from_entry=True)
        except ValueError as error:
            assert 'machine unwind path escapes' in str(error)
        else:
            raise AssertionError('noreturn throwing call incorrectly ignored')
        count += 1
    print(f'Worker invoke inventory and later-call cleanup reject {count} regressions')


if __name__ == '__main__':
    main()
