#!/usr/bin/env python3
"""Reject allocation substitutions and scalar inlined cleanup shortening."""
import re
import batch_worker_scalar as check

SPAWN = '_ZN3std3sys3pal4unix6thread6Thread3new17h1234E'
GROW = '_RNvMs5_NtCs123_5alloc7raw_vecNtB5_11RawVecInner11finish_growCs123_24brynja_hash_parallel_std'
CALL = 'call fastcc void @clear(ptr nonnull %storage.scalar, i64 %width)'
BODY = '''define void @coordinator(i64 %workers, i64 %groups, i1 %cond, ptr %foreign) {
start:
%result = alloca [24 x i8], align 8
br label %widthblock
widthblock:
%width = tail call noundef i64 @llvm.umin.i64(i64 %workers, i64 %groups)
%zero = icmp eq i64 %width, 0
br i1 %zero, label %join, label %grow
grow:
call void @llvm.lifetime.start.p0(ptr nonnull %result)
call fastcc void @GROW(ptr noalias nofree noundef align 8 captures(none) dereferenceable(24) %result, i64 0, ptr nonnull inttoptr (i64 1 to ptr), i64 noundef %width, i64 noundef range(i64 1, 9) 1, i64 noundef range(i64 24, 257) 256)
%tag = load i64, ptr %result, align 8
%failed = trunc nuw i64 %tag to i1
br i1 %failed, label %failure, label %success
failure:
call void @llvm.lifetime.end.p0(ptr nonnull %result)
ret void
success:
%field = getelementptr inbounds nuw i8, ptr %result, i64 8
%allocated = load ptr, ptr %field, align 8
call void @llvm.lifetime.end.p0(ptr nonnull %result)
br label %initialized
initialized:
br label %join
join:
%storage.scalar = phi ptr [ %allocated, %initialized ], [ inttoptr (i64 1 to ptr), %widthblock ]
call void @SPAWN()
br i1 %cond, label %ok, label %error
ok:
CALL
ret void
error:
CALL
ret void
}'''.replace('GROW', GROW).replace('SPAWN', SPAWN).replace('CALL', CALL)


def rejects(body):
    try:
        check.inspect(body, 'clear')
    except ValueError:
        return
    raise AssertionError('scalar argument mutation survived: ' + body)


def main():
    check.inspect(BODY, 'clear')
    check.inspect(re.sub(r'%width\b', '%renamed_width', BODY.replace('%result', '%renamed')), 'clear')
    count = 0
    for before, after in (
        ('i64 %width)', 'i64 0)'), ('i64 %width)', 'i64 1)'),
        ('ptr nonnull %storage.scalar,', 'ptr nonnull %foreign,'),
        ('%allocated, %initialized', '%foreign, %initialized'),
        ('inttoptr (i64 1 to ptr), %widthblock', 'null, %widthblock'),
        ('icmp eq i64 %width, 0', 'icmp ne i64 %width, 0'),
        ('label %join, label %grow', 'label %grow, label %join'),
        ('i64 noundef %width,', 'i64 noundef 0,'),
        ('range(i64 24, 257) 256', 'range(i64 24, 257) 255'),
        ('range(i64 1, 9) 1', 'range(i64 1, 9) 8'),
        ('i64 8\n', 'i64 16\n'), ('load ptr, ptr %field', 'load ptr, ptr %foreign'),
        ('load i64, ptr %result', 'load i64, ptr %foreign'),
        ('trunc nuw i64 %tag', 'trunc nuw i64 %width'),
        ('llvm.umin.i64', 'llvm.umax.i64'), (GROW, GROW + '_unreviewed'),
        ('success:\n', 'success:\nstore ptr %foreign, ptr %result, align 8\n'),
        ('initialized:\n', 'initialized:\nstore ptr %result, ptr %foreign, align 8\n'),
        ('initialized:\n', 'initialized:\ncall void @escape(ptr %field)\n'),
        ('initialized:\n', 'initialized:\n%alias = getelementptr i8, ptr %result, i64 0\n'),
        ('initialized:\n', 'initialized:\n%alias = ptrtoint ptr %result to i64\n'),
        ('initialized:\n', 'initialized:\ncall void @escape(ptr %result)\n'),
        ('ok:\n', 'ok:\n%short = sub i64 %width, 1\n'),
    ):
        changed = BODY.replace(before, after)
        if before == 'ok:\n':
            changed = changed.replace(CALL, CALL.replace('i64 %width)', 'i64 %short)'), 1)
        assert changed != BODY
        rejects(changed)
        count += 1
    # Successful allocation must dominate the incoming allocated pointer.
    rejects(BODY.replace('failure:\ncall void @llvm.lifetime.end.p0(ptr nonnull %result)\nret void',
                         'failure:\nbr label %success'))
    count += 1
    # A loop through initialization after spawn cannot establish a fresh owner.
    rejects(BODY.replace('ok:\n' + CALL + '\nret void', 'ok:\nbr label %widthblock'))
    count += 1
    loop = BODY.replace('br i1 %cond, label %ok, label %error', '''br label %loop
loop:
%p = phi ptr [ %storage.scalar, %join ], [ %p, %loop ]
%n = phi i64 [ %width, %join ], [ %n, %loop ]
br i1 %cond, label %loop, label %done
done:
br i1 %cond, label %ok, label %error''').replace(CALL, 'call fastcc void @clear(ptr nonnull %p, i64 %n)')
    check.inspect(loop, 'clear')
    rejects(loop.replace('[ %n, %loop ]', '[ 0, %loop ]'))
    rejects(loop.replace('[ %p, %loop ]', '[ %foreign, %loop ]'))
    count += 2
    print(f'Scalar worker arguments reject {count} allocation/extent/escape/loop regressions')


if __name__ == '__main__':
    main()
