#!/usr/bin/env python3
"""Regressions for inlined Storage argument equality and header non-escape."""
import batch_worker_provenance as check

CLEAR, DROP = 'clear', 'drop'
SPAWN = '_ZN3std3sys3pal4unix6thread6Thread3new17h1234E'
SETUP = '''define void @coordinator(ptr %base, i64 %length, ptr %foreign, i1 %cond) {
start:
%storage = alloca [24 x i8], align 8
%bp = getelementptr inbounds i8, ptr %storage, i64 8
%lp = getelementptr inbounds i8, ptr %storage, i64 16
store ptr %base, ptr %bp, align 8
store i64 %length, ptr %lp, align 8
br label %spawn
spawn:
call void @SPAWN()
'''.replace('SPAWN', SPAWN)
CALL = 'call fastcc void @clear(ptr nonnull %p, i64 %n)'
EXITS = '''br i1 %cond, label %ok, label %error
ok:
CALL
ret void
error:
CALL
ret void
}'''.replace('CALL', CALL)
BODY = SETUP + '''br i1 %cond, label %left, label %right
left:
%pl = load ptr, ptr %bp, align 8
%nl = load i64, ptr %lp, align 8
br label %join
right:
%pr = load ptr, ptr %bp, align 8
%nr = load i64, ptr %lp, align 8
br label %join
join:
%p = phi ptr [ %pl, %left ], [ %pr, %right ]
%n = phi i64 [ %nl, %left ], [ %nr, %right ]
''' + EXITS
LOOP = SETUP + '''br label %loop
loop:
%p = phi ptr [ %base, %spawn ], [ %p, %loop ]
%n = phi i64 [ %length, %spawn ], [ %n, %loop ]
br i1 %cond, label %loop, label %done
done:
''' + EXITS


def rejects(body):
    try:
        check.inspect(body, CLEAR, DROP)
    except ValueError:
        return
    raise AssertionError('inlined argument regression survived: ' + body)


def main():
    check.inspect(BODY, CLEAR, DROP)
    check.inspect(LOOP, CLEAR, DROP)
    check.inspect(BODY.replace('%storage', '%storage.renamed'), CLEAR, DROP)
    check.inspect(BODY.replace(CALL, 'call void @drop(ptr %storage)'), CLEAR, DROP)
    # Stores establish current equality; it need not have originated in a load.
    check.inspect(BODY.replace('%pr, %right', '%base, %right').replace('%nr, %right', '%length, %right'), CLEAR, DROP)
    count = 0
    for before, after in (
        ('ptr nonnull %p', 'ptr nonnull %foreign'), ('i64 %n)', 'i64 0)'),
        ('i64 %n)', 'i64 1)'), ('ptr nonnull %p', 'ptr nonnull %storage'),
        ('ptr nonnull %p', 'ptr nonnull null'),
        ('%pr, %right', '%foreign, %right'), ('%nr, %right', '0, %right'),
        ('%nl, %left', '0, %left'), ('%pl, %left', '%foreign, %left'),
        ('i64 8\n', 'i64 16\n'), ('i64 16\n', 'i64 8\n'),
        ('load ptr, ptr %bp', 'load ptr, ptr %lp'),
        ('load i64, ptr %lp', 'load i32, ptr %lp'),
        ('%nr = load i64, ptr %lp, align 8', '%nr = add i64 %length, -1'),
        ('%pr = load ptr, ptr %bp, align 8', '%pr = getelementptr i8, ptr %base, i64 256'),
        ('left:\n', 'left:\nstore i64 0, ptr %lp, align 8\n'),
        ('left:\n', 'left:\nstore ptr %foreign, ptr %bp, align 8\n'),
        ('left:\n', 'left:\nstore i64 0, ptr %storage, align 8\n'),
        ('left:\n', 'left:\ncall void @unknown(ptr %storage)\n'),
        ('left:\n', 'left:\ncall void @unknown(ptr %lp)\n'),
        ('br label %spawn', 'store ptr %storage, ptr %foreign, align 8\nbr label %spawn'),
        ('br label %spawn', 'store ptr %bp, ptr %foreign, align 8\nbr label %spawn'),
        ('br label %spawn', '%escape = ptrtoint ptr %storage to i64\nbr label %spawn'),
        ('br label %spawn', '%escape = getelementptr i8, ptr %bp, i64 0\nbr label %spawn'),
        ('br label %spawn', 'call void @llvm.memcpy.p0.p0.i64(ptr %foreign, ptr %storage, i64 24, i1 false)\nbr label %spawn'),
        ('left:\n', 'left:\ncall void @llvm.lifetime.start.p0(ptr nonnull %storage)\n'),
    ):
        assert before in BODY
        rejects(BODY.replace(before, after))
        count += 1
    rejects(BODY.replace(CALL, 'call void @drop(ptr %foreign)'))
    count += 1
    # A later loop predecessor must invalidate the optimistic first iteration.
    for dest, value in (('%n', '0'), ('%p', '%foreign')):
        rejects(LOOP.replace(f'[ {dest}, %loop ]', f'[ {value}, %loop ]'))
        count += 1
    # Re-executing an SSA definition kills its earlier iteration's equality.
    changed = LOOP.replace('[ %n, %loop ]', '[ %next, %loop ]').replace(
        'br i1 %cond, label %loop', '%next = add i64 %n, 1\nbr i1 %cond, label %loop')
    rejects(changed)
    count += 1
    # Phi operands are read simultaneously, not from earlier phis in this block.
    facts = (frozenset({'%a'}), frozenset({'%b'}))
    swapped = check.phis(['%a = phi ptr [ %b, %back ]', '%b = phi i64 [ %a, %back ]'], 'back', facts)
    assert swapped == (frozenset({'%b'}), frozenset({'%a'}))
    # Reservation can change base/length: pre-call equalities must be invalidated.
    symbol = '_RNvMs2_NtCs123_5alloc7raw_vecNtB5_11RawVecInner10grow_exactCs123_24brynja_hash_parallel_std'
    grow = 'call fastcc i64 @' + symbol + '(ptr %storage, i64 noundef 2, i64 noundef 1, i64 noundef 256)'
    check.inspect(BODY.replace('br label %spawn', grow + '\nbr label %spawn'), CLEAR, DROP)
    rejects(LOOP.replace('br label %spawn', grow + '\nbr label %spawn'))
    rejects(BODY.replace('left:\n', 'left:\n' + grow + '\n'))
    count += 2
    # An ordinary SSA redefinition must not retain an old iteration's equality.
    lines = ['%n = add i64 %length, 1', CALL]
    try:
        check.transfer(lines, True, (frozenset({'%p'}), frozenset({'%n'})),
                       [(None, None), (None, None)], CLEAR, True)
    except ValueError:
        count += 1
    else:
        raise AssertionError('stale loop-iteration equality survived')
    # The same SSA value reaches a join along two paths, but a reservation on
    # only one path destroys its equality to the header there. No phi is needed.
    fork = SETUP.split('br label %spawn')[0] + '''br i1 %cond, label %reserve, label %skip
reserve:
GROW
br label %spawn
skip:
br label %spawn
spawn:
call void @SPAWN()
'''.replace('GROW', grow).replace('SPAWN', SPAWN) + EXITS.replace('%p,', '%base,').replace('%n)', '%length)')
    rejects(fork)
    count += 1
    print(f'Inlined memory-backed arguments reject {count} pointer/length/escape/loop regressions')


if __name__ == '__main__':
    main()
