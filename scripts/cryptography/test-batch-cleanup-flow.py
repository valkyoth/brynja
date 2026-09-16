#!/usr/bin/env python3
"""Reject field, slice, call, branch and indirect-call provenance regressions."""
import batch_cleanup_flow as check
import mir_cleanup_flow as flow


def rejects(call):
    try:
        call()
    except (ValueError, flow.MirCleanupFlowError):
        return
    raise AssertionError('invalid cleanup accepted')


def fixture(panic):
    edge = 'continue' if panic == 'unwind' else 'unreachable'
    return '''fn fixture(_1: &mut Owner) -> () {
    bb0: {
        _2 = &mut ((*_1).0: [[u8; 4]; 2]);
        _3 = copy _2 as &mut [[u8; 4]] (PointerCoercion(Unsize, Implicit));
        _4 = slice::<impl [[u8; 4]]>::as_flattened_mut(move _3) -> [return: bb1, unwind EDGE];
    }
    bb1: {
        _5 = clear_owned_region(move _4) -> [return: bb2, unwind EDGE];
    }
    bb2: {
        _6 = &mut ((*_1).1: Nested);
        _7 = Nested::wipe(move _6) -> [return: bb3, unwind EDGE];
    }
    bb3: {
        return;
    }
}
'''.replace('EDGE', edge)


EXPECTED = [('0', '[u8]', 'clear_owned_region('), ('1', 'Nested', 'Nested::wipe(')]


def mir_tests():
    count = 0
    for panic in ('abort', 'unwind'):
        good = fixture(panic)
        check.linear_fields(good, EXPECTED, panic, 'Owner')
        changes = (
            ('((*_1).0:', '((*_1).1:'),
            ('((*_1).1: Nested)', '((*_1).0: Nested)'),
            ('Nested::wipe(', 'Ordinary::wipe('),
            ('clear_owned_region(', 'omitted_clear('),
            ('as_flattened_mut(', 'partial_slice('),
            ('&mut [[u8; 4]] (PointerCoercion', '&mut [[u8; 2]] (PointerCoercion'),
            ('move _4)', 'move _3)'),
            ('move _4)', 'move _99)'),
            ('move _4)', 'move _4, const 1_usize)'),
            ('move _6)', 'move _1)'),
            ('_5 = clear_owned_region', '_4 = &mut ((*_1).1: Nested);\n        _5 = clear_owned_region'),
            ('bb1, unwind', 'bb3, unwind'),
            ('bb2, unwind', 'bb0, unwind'),
            ('        _6 =', '        (*_1).0 = const Zero;\n        _6 ='),
            ('        _6 =', '        escape(copy _1);\n        _6 ='),
            ('        return;', '        return;\n        escape(copy _1);'),
            ('    bb3: {', '    bb4: {\n        return;\n    }\n    bb3: {'),
        )
        for before, after in changes:
            assert before in good
            rejects(lambda: check.linear_fields(good.replace(before, after), EXPECTED, panic, 'Owner'))
            count += 1
        wrong_panic = 'unwind' if panic == 'abort' else 'abort'
        rejects(lambda: check.linear_fields(good, EXPECTED, wrong_panic, 'Owner'))
        count += 1
        guard = '''fn drop(_1: &mut Operation) -> () {
    bb0: {
        _4 = no_retag copy ((*_1).1: &mut batch::Workspace);
        _2 = batch::Workspace::wipe(move _4) -> [return: bb1, unwind EDGE];
    }
    bb1: {
        return;
    }
}'''.replace('EDGE', 'continue' if panic == 'unwind' else 'unreachable')
        check.entry_cleanup(guard, 'batch::Workspace::wipe(', 'batch::Workspace', panic)
        for before, after in (
            ('((*_1).1:', '((*_1).0:'), ('move _4)', 'move _1)'),
            ('batch::Workspace::wipe(', 'batch::Workspace::omitted('),
            ('        _4 =', '        return;\n        _4 ='),
            ('        _4 =', '        escape(copy _1);\n        _4 ='),
        ):
            rejects(lambda: check.entry_cleanup(guard.replace(before, after), 'batch::Workspace::wipe(', 'batch::Workspace', panic))
            count += 1
    return count


def assembly_tests():
    direct = 'bl _Rclear\nb _Rnested'
    assert check.assembly_calls(direct) == ['_Rclear', '_Rnested']
    indirect = 'movq _Rclear@GOTPCREL(%rip), %r14\ncallq *%r14\njmpq _Rnested'
    assert check.assembly_calls(indirect) == ['_Rclear', '_Rnested']
    changes = [
        ('callq *%r14', clobber + '\ncallq *%r14') for clobber in (
            'movq $0, %r14', 'movl $0, %r14d', 'addq $1, %r14',
            'xchgq %r14, %rax', 'retq', 'je .Lskip',
        )
    ] + [('%r14', '%rax'), ('callq *%r14', 'callq *%r15'),
         ('jmpq _Rnested', 'jmpq .Lskip'), ('jmpq _Rnested', 'jmpq _Rnested\ncallq *%r14')]
    for before, after in changes:
        rejects(lambda: check.assembly_calls(indirect.replace(before, after)))
    for branch in ('b.eq .Lskip', 'cbz x0, .Lskip', 'tbnz x0, #0, .Lskip', 'ret'):
        rejects(lambda: check.assembly_calls(branch + '\n' + direct))
    llvm = 'define void @_ROwnerwipe() {\n  ret void\n}'
    assert check.llvm_function(llvm, ('Owner', 'wipe')) == llvm
    rejects(lambda: check.llvm_function(llvm + '\n' + llvm, ('Owner', 'wipe')))
    rejects(lambda: check.llvm_function(llvm, ('Missing',)))
    assembly = '_ROwnerwipe:\n bl _Rclear\n_Rnext:\n ret'
    assert '_Rnext' not in check.assembly_function(assembly, ('Owner', 'wipe'))
    rejects(lambda: check.assembly_function(assembly + '\n' + assembly, ('Owner', 'wipe')))
    rejects(lambda: check.assembly_function(assembly, ('Missing',)))
    return len(changes) + 8


def main():
    count = mir_tests() + assembly_tests()
    print(f'Batch cleanup field/CFG/call provenance: PASS; {count} malformed artifacts rejected')


if __name__ == '__main__':
    main()
