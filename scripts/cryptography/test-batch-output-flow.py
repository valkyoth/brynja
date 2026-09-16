#!/usr/bin/env python3
"""Exercise output iteration with symbolic positive lengths and hostile LLVM."""
import batch_output_flow as flow

CLEAR = '_ZN11brynja_core13secret_memory18clear_owned_region17h1234abcdE'
FIXTURE = '''define void @output(ptr %self) {
start:
  br label %head
head:
  %index = phi i64 [ 0, %start ], [ %next, %advance ]
  %done = icmp eq i64 %index, 32
  br i1 %done, label %finish, label %slot
slot:
  %address = getelementptr inbounds nuw i8, ptr %self, i64 %index
  %next = add nuw nsw i64 %index, 16
  %data = load ptr, ptr %address, align 8
  %absent = icmp eq ptr %data, null
  br i1 %absent, label %advance, label %length
length:
  %lenptr = getelementptr inbounds nuw i8, ptr %address, i64 8
  %len = load i64, ptr %lenptr, align 8
  %empty = icmp eq i64 %len, 0
  br i1 %empty, label %advance, label %clear
clear:
  %ignored = call noundef i8 @CLEAR(ptr noalias %data, i64 noundef %len)
  br label %advance
advance:
  br label %head
finish:
  %meta = getelementptr inbounds nuw i8, ptr %self, i64 32
  %ignoredmeta = call noundef i8 @CLEAR(ptr noalias %meta, i64 noundef 2)
  ret void
}'''.replace('CLEAR', CLEAR)


def rejects(source):
    try:
        flow.check(source, 2, [(32, 2)])
    except ValueError:
        return
    raise AssertionError('invalid output destructor accepted')


def main():
    assert flow.check(FIXTURE, 2, [(32, 2)]) == 9
    assert flow.check(FIXTURE.replace('inbounds nuw ', ''), 2, [(32, 2)]) == 9
    # Equivalent pointer induction also appears in supported compiler output.
    pointer = FIXTURE.replace('%index = phi i64 [ 0, %start ]', '%index = phi ptr [ %self, %start ]')
    pointer = pointer.replace('%done = icmp eq i64 %index, 32', '%end = getelementptr inbounds i8, ptr %self, i64 32\n  %done = icmp eq ptr %index, %end')
    pointer = pointer.replace('ptr %self, i64 %index', 'ptr %index, i64 0')
    pointer = pointer.replace('add nuw nsw i64 %index, 16', 'getelementptr inbounds i8, ptr %index, i64 16')
    assert flow.check(pointer, 2, [(32, 2)]) == 9
    mutations = (
        ('[ 0, %start ]', '[ 16, %start ]'),
        ('i64 %index, 32', 'i64 %index, 16'),
        ('i64 %index, 32', 'i64 %index, 48'),
        ('i64 %index, 16', 'i64 %index, 32'),
        ('i64 %index, 16', 'i64 %index, 0'),
        ('[ %next, %advance ]', '[ %index, %advance ]'),
        ('[ %next, %advance ]', '[ %unknown, %advance ]'),
        ('[ %next, %advance ]', '[ %next, %start ]'),
        ('br i1 %absent, label %advance, label %length', 'br label %length'),
        ('br i1 %empty, label %advance, label %clear', 'br label %advance'),
        ('icmp eq ptr %data, null', 'icmp ne ptr %data, null'),
        ('icmp eq i64 %len, 0', 'icmp ne i64 %len, 0'),
        ('icmp eq i64 %len, 0', 'icmp eq i64 %len, 1'),
        ('ptr %address, i64 8', 'ptr %address, i64 0'),
        ('ptr %self, i64 %index', 'ptr %self, i64 0'),
        ('ptr %address, align 8', 'ptr %data, align 8'),
        ('i64 noundef %len', 'i64 noundef 1'),
        ('ptr noalias %data', 'ptr noalias %self'),
        ('i64 noundef 2)', 'i64 noundef 1)'),
        ('ptr %self, i64 32', 'ptr %self, i64 31'),
        ('@' + CLEAR, '@untrusted_' + CLEAR),
        ('  ret void', '  store i8 1, ptr %self\n  ret void'),
        ('  ret void', '  ret void\n  store i8 1, ptr %self'),
        ('  ret void', '  br label %missing'),
        ('start:\n  br label %head', 'start:\n  ret void'),
        ('finish:', 'head:'),
        ('\n}', '\ndead:\n  ret void\n}'),
    )
    for before, after in mutations:
        assert before in FIXTURE
        rejects(FIXTURE.replace(before, after))
    # No final visited-block check alone can excuse a duplicated clearing call.
    line = '  %ignored = call noundef i8 @' + CLEAR + '(ptr noalias %data, i64 noundef %len)'
    rejects(FIXTURE.replace(line, line + '\n' + line.replace('%ignored', '%extra')))
    print(f'Batch output LLVM interpreter: PASS; {len(mutations) + 1} loop/provenance/clear regressions rejected')


if __name__ == '__main__':
    main()
