#!/usr/bin/env python3
"""Regress retained glue provenance, deallocation order and exceptional exits."""
import batch_worker_drop_glue as check

CLEAR = '_ZN24brynja_hash_parallel_std9execution5batch6worker7Storage5clear17h1234E'
FREE = '_RNvCs123abc_7___rustc14___rust_dealloc'
HEADER = 'define internal fastcc void @glue(ptr noalias readonly align 8 dereferenceable(24) %owner) unnamed_addr #0 {'
START = '''start:
%bp = getelementptr inbounds nuw i8, ptr %owner, i64 8
%base = load ptr, ptr %bp, align 8
%lp = getelementptr inbounds nuw i8, ptr %owner, i64 16
%len = load i64, ptr %lp, align 8
'''
CALL = 'fastcc void @' + CLEAR + '(ptr nonnull %base, i64 %len)'
DEALLOC = ('tail call void @' + FREE + '(ptr noundef nonnull %base, i64 noundef %size, '
           'i64 noundef range(i64 1, -9223372036854775807) 1)')
NORMAL = '''normal:
%cap = load i64, ptr %owner, align 8
%empty = icmp eq i64 %cap, 0
br i1 %empty, label %done, label %free
free:
%size = shl nuw i64 %cap, 8
FREE
br label %done
done:
ret void
'''.replace('FREE', DEALLOC)
EXCEPTION = ('''cleanup:
%exception = landingpad { ptr, i32 }
cleanup
''' + NORMAL.replace('normal:\n', '').replace('%cap', '%ecap').replace('%empty', '%eempty').replace(
    '%size', '%esize').replace('%done', '%edone').replace('%free', '%efree').replace(
    'free:', 'efree:').replace('done:', 'edone:').replace('ret void', 'resume { ptr, i32 } %exception'))


def fixture(panic):
    call = ('invoke ' + CALL + '\nto label %normal unwind label %cleanup\n' if panic == 'unwind'
            else 'tail call ' + CALL + '\nbr label %normal\n')
    return HEADER + '\n' + START + call + NORMAL + (EXCEPTION if panic == 'unwind' else '') + '}'


def rejects(body, panic):
    try:
        check.llvm_check(body, CLEAR, panic)
    except ValueError:
        return
    raise AssertionError('drop-glue regression survived:\n' + body)


def main():
    count = 0
    for panic in ('abort', 'unwind'):
        body = fixture(panic)
        check.llvm_check(body, CLEAR, panic)
        check.llvm_check(body.replace('%owner', '%renamed'), CLEAR, panic)
        check.llvm_check(body.replace('normal:', '"quoted.normal":').replace('%normal', '%"quoted.normal"'), CLEAR, panic)
        for before, after in (
            ('i64 8\n', 'i64 0\n'), ('i64 16\n', 'i64 8\n'),
            ('load i64', 'load i32'), ('load ptr', 'load i64'), ('align 8', 'align 4'),
            ('ptr nonnull %base,', 'ptr nonnull %owner,'), ('i64 %len)', 'i64 0)'),
            ('i64 %len)', 'i64 1)'), ('ptr %bp,', 'ptr %lp,'), ('ptr %lp,', 'ptr %bp,'),
            ('icmp eq', 'icmp ne'), ('i64 %cap, 8', 'i64 %cap, 7'),
            ('i64 %cap, 8', 'i64 %len, 8'), ('nonnull %base, i64 noundef', 'nonnull %owner, i64 noundef'),
            ('range(i64 1, -9223372036854775807) 1', 'range(i64 1, -9223372036854775807) 2'),
            ('ptr %owner, align 8', 'ptr %lp, align 8'),
            ('label %done, label %free', 'label %free, label %done'),
            (DEALLOC, ''), (DEALLOC, DEALLOC + '\n' + DEALLOC),
            (DEALLOC, 'store i8 0, ptr %base'),
            ('ret void', 'resume invalid'), ('ret void', 'unreachable'),
            ('ret void', 'br label %start'), ('ret void', 'ret void\nstore i8 1, ptr %base'),
            ('%len = load', '%owner = load'), ('%lp = getelementptr', '%bp = getelementptr'),
            (CLEAR, CLEAR + '_wrong'), (FREE, FREE + '_wrong'),
            ('unwind label %cleanup', 'unwind label %normal'),
            ('to label %normal', 'to label %done'),
            ('resume { ptr, i32 } %exception', 'ret void'),
            ('resume { ptr, i32 } %exception', 'resume { ptr, i32 } %base'),
            ('invoke ' + CALL, 'invoke ' + CALL + '\n' + DEALLOC),
        ):
            if before in body:
                rejects(body.replace(before, after), panic)
                count += 1
    machine_count = 0
    for template in check.entry_templates(CLEAR):
        source = '\n'.join(template)
        check.assembly_check(source, CLEAR)
        check.assembly_check('.Lfunc_begin12:\n.cfi_startproc\n' + source, CLEAR)
        for index in range(len(template)):
            for replacement in ('', 'ret', 'unknown_op', 'callq _wrong'):
                mutant = '\n'.join(template[:index] + [replacement] + template[index + 1:])
                try:
                    check.assembly_check(mutant, CLEAR)
                except ValueError:
                    machine_count += 1
                else:
                    raise AssertionError('glue prefix regression survived')
        for prefix in ('.cfi_endproc', '.byte 0', 'jmp .Ltmp1', 'LBB1_0:',
                       '.cfi_startproc; ret', '.cfi_endproc; ret'):
            try:
                check.assembly_check(prefix + '\n' + source, CLEAR)
            except ValueError:
                machine_count += 1
            else:
                raise AssertionError('glue boundary regression survived')
    print(f'Worker retained drop glue rejects {count} LLVM and {machine_count} entry-prefix regressions')


if __name__ == '__main__':
    main()
