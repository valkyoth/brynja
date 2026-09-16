#!/usr/bin/env python3
"""Reject shortened, shifted, bypassed or length-independent worker clear loops."""
import batch_worker_cleanup as check

FIXTURE = '''define internal fastcc void @clear(ptr %base, i64 %count) {
start:
%nonnull = icmp ne ptr %base, null
tail call void @llvm.assume(i1 %nonnull)
%bytes = shl nuw nsw i64 %count, 8
%end = getelementptr inbounds nuw i8, ptr %base, i64 %bytes
%empty = icmp eq i64 %count, 0
br i1 %empty, label %done, label %loop
loop:
%cursor = phi ptr [ %next, %loop ], [ %base, %start ]
%next = getelementptr inbounds nuw i8, ptr %cursor, i64 256
%r = tail call noundef i8 @_ZN11brynja_core13secret_memory18clear_owned_region17h1234abcdE(ptr noalias noundef nonnull %cursor, i64 noundef 256)
%last = icmp eq ptr %next, %end
br i1 %last, label %done, label %loop
done:
ret void
}'''


def main():
    check.loop_check(FIXTURE)
    check.loop_check(FIXTURE.replace('%nonnull = icmp ne ptr %base, null\ntail call void @llvm.assume(i1 %nonnull)\n', ''))
    typed = FIXTURE.replace('%bytes = shl nuw nsw i64 %count, 8\n', '').replace(
        'i8, ptr %base, i64 %bytes', '[4 x [64 x i8]], ptr %base, i64 %count')
    check.loop_check(typed)
    count = 0
    for before, after in (
        ('i64 %count, 8', 'i64 %count, 7'), ('i64 %count, 0', 'i64 %count, 1'),
        ('i64 256', 'i64 255'), ('i64 noundef 256', 'i64 noundef 255'),
        ('%cursor, i64 noundef', '%next, i64 noundef'),
        ('[ %next, %loop ]', '[ %base, %loop ]'),
        ('[ %base, %start ]', '[ %end, %start ]'),
        ('icmp eq ptr %next, %end', 'icmp eq ptr %cursor, %end'),
        ('br i1 %empty, label %done, label %loop', 'br i1 %empty, label %loop, label %done'),
        ('br i1 %last, label %done, label %loop', 'br label %done'),
        ('llvm.assume(i1 %nonnull)', 'llvm.assume(i1 %empty)'),
        ('18clear_owned_region', '18ordinary_region'),
        ('ret void', 'store i8 1, ptr %base\nret void'),
        ('shl nuw nsw', 'shl'),
    ):
        assert before in FIXTURE
        try:
            check.loop_check(FIXTURE.replace(before, after))
        except ValueError:
            count += 1
        else:
            raise AssertionError('worker loop mutation survived')
    for before, after in (('[4 x [64 x i8]]', '[3 x [64 x i8]]'), ('i64 %count\n', 'i64 1\n')):
        try:
            check.loop_check(typed.replace(before, after))
        except ValueError:
            count += 1
        else:
            raise AssertionError('typed-end worker loop mutation survived')
    print(f'Worker cleanup loop: PASS; {count} stride/bound/clear/control-flow regressions rejected')


if __name__ == '__main__':
    main()
