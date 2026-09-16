#!/usr/bin/env python3
"""Reject post-spawn cleanup bypasses and malformed inlined LLVM graphs."""
import batch_worker_inline as check

SPAWN = '_ZN3std3sys3pal4unix6thread6Thread3new17habc123E'
CLEAR, DROP = '_clear_storage', '_drop_storage'
BODY = '''define void @coordinator() {
start:
%x = invoke i64 @SPAWN()
to label %normal unwind label %error
normal:
call void @CLEAR()
br label %exit
error:
%exception = landingpad { ptr, i32 }
cleanup
call void @DROP()
resume { ptr, i32 } %exception
exit:
ret void
}'''.replace('SPAWN', SPAWN).replace('CLEAR', CLEAR).replace('DROP', DROP)


def rejects(body):
    try:
        check.inspect(body, CLEAR, DROP, {'_abort'})
    except ValueError:
        return
    raise AssertionError('inline cleanup regression survived:\n' + body)


def main():
    check.inspect(BODY, CLEAR, DROP, set())
    check.inspect(BODY.replace('normal', '"normal.with-hyphen"'), CLEAR, DROP, set())
    # Loop joins retain both possible dirty states; eventual exits still clear.
    loop = BODY.replace('call void @CLEAR()', 'br i1 %again, label %normal, label %clear\nclear:\ncall void @CLEAR()')
    check.inspect(loop, CLEAR, DROP, set())
    repeated = BODY.replace('start:', 'start:\nbr label %work\nwork:').replace(
        'br label %exit', 'br i1 %again, label %work, label %exit')
    check.inspect(repeated, CLEAR, DROP, set())
    count = 0
    for before, after in (
        ('call void @' + CLEAR + '()', ''), ('call void @' + DROP + '()', ''),
        (CLEAR, '_wrong'), (DROP, '_wrong'), (SPAWN, '_wrong'),
        ('to label %normal', 'to label %exit'), ('unwind label %error', 'unwind label %exit'),
        ('call void @' + CLEAR + '()', 'ret void'),
        ('ret void', 'unreachable'), ('br label %exit', 'br label %missing'),
        ('br label %exit', 'indirectbr ptr %address, [label %exit]'),
        ('br label %exit', 'callbr void @fn() to label %exit [label %error]'),
        ('exit:', 'normal:'), ('error:', ''),
        ('call void @' + CLEAR + '()', 'call void @' + CLEAR + '()\n%x2 = call i64 @' + SPAWN + '()'),
        ('normal:', 'normal:\nbr label %exit'),
        ('normal:', 'normal:\ncall void asm sideeffect "ret", ""()'),
    ):
        rejects(BODY.replace(before, after))
        count += 1
    # An early clear must not sanitize a later spawn on either branch.
    rejects(BODY.replace('start:', 'start:\ncall void @' + CLEAR + '()').replace('normal:\ncall void @' + CLEAR + '()', 'normal:'))
    count += 1
    rejects(loop.replace('call void @' + CLEAR + '()', ''))
    count += 1
    diamond = BODY.replace('normal:', 'normal:\nbr i1 %condition, label %cleared, label %exit\ncleared:')
    rejects(diamond)
    count += 1
    # Abort is not cleanup evidence, but a real nonreturning exit is allowed if
    # other post-spawn paths still establish non-vacuous ordinary completion.
    abort = BODY.replace('normal:', 'normal:\nbr i1 %condition, label %clear, label %stop\nstop:\ncall void @_abort()\nunreachable\nclear:')
    check.inspect(abort, CLEAR, DROP, {'_abort'})
    rejects(abort.replace('call void @_abort()', 'call void @_unreviewed()'))
    count += 1
    invalid = BODY.replace('normal:', 'normal:\nswitch i8 %tag, label %invalid [\ni8 0, label %clear\ni8 1, label %clear\n]\ninvalid:\nunreachable\nclear:')
    check.inspect(invalid, CLEAR, DROP, set())
    rejects(invalid.replace('i8 1, label %clear', 'i8 1, label %invalid'))
    count += 1
    rejects(invalid.replace('switch i8 %tag, label %invalid [\ni8 0, label %clear\ni8 1, label %clear\n]',
                            'br i1 %tag, label %clear, label %invalid'))
    count += 1
    noreturn = BODY.replace('normal:', 'normal:\ninvoke void @_abort()\nto label %invalid unwind label %clear\ninvalid:\nunreachable\nclear:')
    check.inspect(noreturn, CLEAR, DROP, {'_abort'})
    rejects(noreturn.replace('@_abort()', '@_unreviewed()'))
    count += 1
    phi = '''define void @cfg() {
start:
switch i8 %tag, label %invalid [
i8 0, label %join
i8 1, label %join
]
join:
%value = phi i64 [ 7, %start ], [ 7, %start ]
ret void
invalid:
unreachable
}'''
    check.cfg.parse(phi)
    for before, after in (
        ('[ 7, %start ], [ 7, %start ]', '[ 7, %start ]'),
        ('[ 7, %start ], [ 7, %start ]', '[ 7, %start ], [ 8, %start ]'),
        ('[ 7, %start ], [ 7, %start ]', '[ 7, %start ], [ 7, %missing ]'),
        ('i8 1,', 'i8 0,'), ('i8 1,', 'i16 1,'),
        ('%value = phi', 'call void @_nothing()\n%value = phi'),
    ):
        try:
            check.cfg.parse(phi.replace(before, after))
        except ValueError:
            count += 1
        else:
            raise AssertionError('CFG/phi regression survived')
    print(f'Inlined worker cleanup rejects {count} call/exit/loop/CFG/phi regressions')


if __name__ == '__main__':
    main()
