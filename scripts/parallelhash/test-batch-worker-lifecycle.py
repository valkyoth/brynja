#!/usr/bin/env python3
"""Reject missing local Drop/unwind edges and incorrect worker guard lifetimes."""
import re

import batch_worker_cleanup  # Shared helper path.
import batch_worker_lifecycle as check


def fixture(panic):
    blocks = {
        'bb0': ["_6 = execution::batch::worker::Operation::<'_, '_, '_, '_> { root: copy _2, complete: const false };",
                '_7 = live(copy _4) -> [return: bb1, unwind: bb8];'],
        'bb1': ['_20 = execution::batch::worker::Storage(move _21);',
                "_8 = scope::<'_, {closure@crates/brynja-hash-parallel-std/src/execution/batch/worker.rs:151:19: 151:26}, Result<execution::batch::worker::Work, execution::batch::Error>>(move _30) -> [return: bb2, unwind: bb7];"],
        'bb2': ['switchInt(copy _9) -> [0: bb3, otherwise: bb4];'],
        'bb3': ['(_6.1: bool) = const true;', '_0 = ' + check.RESULT + '::Ok(move _31);',
                'drop(_20) -> [return: bb5, unwind: bb8];'],
        'bb4': ['_0 = ' + check.RESULT + '::Err(copy _32);', 'drop(_20) -> [return: bb5, unwind: bb8];'],
        'bb5': ['drop(_6) -> [return: bb6, unwind continue];'],
        'bb6': ['return;'],
        'bb7': ['drop(_20) -> [return: bb8, unwind terminate(cleanup)];'],
        'bb8': ['drop(_6) -> [return: bb9, unwind terminate(cleanup)];'],
        'bb9': ['resume;'],
    }
    if panic == 'abort':
        blocks = {b: [re.sub(r'unwind(?:: bb\d+| continue)', 'unwind unreachable', line) for line in lines]
                  for b, lines in blocks.items() if int(b[2:]) < 7}
    text = ('fn execution::batch::worker::run_with(_1: &Plan<\'_>, _2: &mut Collector<\'_>) -> Result<Work, Error> {\n'
            '    let mut _20: ' + check.STORAGE + ';\n    let mut _6: ' + check.OPERATION + ';\n')
    for b, lines in blocks.items():
        text += '    ' + b + (' (cleanup)' if int(b[2:]) >= 7 else '') + ': {\n'
        text += '\n'.join('        ' + line for line in lines) + '\n    }\n'
    return text + '}\n'


def rejects(source, panic):
    try:
        check.inspect(source, panic)
    except (ValueError, check.flow.MirCleanupFlowError):
        return
    raise AssertionError('worker lifecycle mutation survived:\n' + source)


def main():
    count = 0
    for panic in ('abort', 'unwind'):
        source = fixture(panic)
        check.inspect(source, panic)
        check.inspect(source.replace('_20', '_220').replace('_6', '_206'), panic)
        typed = source.replace('switchInt(copy _9) -> [0: bb3, otherwise: bb4];',
                               '_9 = discriminant(_8);\n        switchInt(copy _9) -> [0: bb3, 1: bb4, otherwise: bb10];')
        typed = typed[:-2] + '    bb10: {\n        unreachable;\n    }\n}\n'
        check.inspect(typed, panic)
        for before, after in (('0: bb3', '0: bb10'), ('1: bb4', '1: bb10'),
                              ('_9 = discriminant(_8)', '_9 = copy _8'),
                              ('return: bb2', 'return: bb10'),
                              ('        unreachable;', '        assume(const false);\n        unreachable;')):
            rejects(typed.replace(before, after), panic)
            count += 1
        cases = [
            ('complete: const false', 'complete: const true'),
            ('root: copy _2', 'root: copy _1'),
            ('(_6.1: bool) = const true;', ''),
            ('(_6.1: bool) = const true;', '(_6.1: bool) = const false;'),
            ('_0 = ' + check.RESULT + '::Err', '(_6.1: bool) = const true;\n        _0 = ' + check.RESULT + '::Err'),
            ('drop(_20) -> [return: bb5,', 'drop(_6) -> [return: bb5,'),
            ('drop(_6) -> [return: bb6,', 'drop(_20) -> [return: bb6,'),
            ('_20 = ' + check.STORAGE + '(move _21);', '_20 = ' + check.STORAGE + '(move _21);\n        _22 = move _20;'),
            ('_20 = ' + check.STORAGE + '(move _21);', '_20 = ' + check.STORAGE + '(move _21);\n        StorageDead(_20);'),
            ('_20 = ' + check.STORAGE + '(move _21);', '_20 = ' + check.STORAGE + '(move _21);\n        _20 = ' + check.STORAGE + '(move _21);'),
            ('_20 = ' + check.STORAGE + '(move _21);', '_20 = ' + check.STORAGE + '(move _21);\n        (_20.0: Vec<Slot>) = move _21;'),
            ('_20 = ' + check.STORAGE + '(move _21);', '_20 = ' + check.STORAGE + '(move _21);\n        _22 = move (_20.0: Vec<Slot>);'),
            ('_20 = ' + check.STORAGE + '(move _21);', ''),
            ('_7 = live(copy _4)', '_0 = live(copy _4)'),
            ('_7 = live(copy _4)', '_7 = std::mem::forget(move _6)'),
            ('_7 = live(copy _4)', '_7 = unknown(copy _4)'),
            ('_7 = live(copy _4)', '_6 = live(copy _4)'),
            ('        _7 = live', '        _2 = copy _3;\n        _7 = live'),
            ('        _7 = live', '        return;\n        _7 = live'),
            ('        _7 = live', '        asm!();\n        _7 = live'),
            ('        _7 = live', '        deinit(_6);\n        _7 = live'),
            ('return: bb1,', 'return: bb6,'),
            ('return: bb2,', 'return: bb6,'),
            ('return: bb2,', 'return: bb_missing,'),
            ('otherwise: bb4', 'otherwise: bb6'),
            ('    bb4: {', '    bb3: {'),
            ('        return;', '        _22 = copy (_20.0: usize);\n        return;'),
            ('        return;', '        unreachable;'),
            ('::Ok(move _31)', '::Err(copy _32)'),
        ]
        for match in re.finditer(r'drop\(_(?:6|20)\) -> \[return: (bb\d+), [^\n]+;', source):
            changed = source[:match.start()] + 'goto -> ' + match[1] + ';' + source[match.end():]
            rejects(changed, panic)
            count += 1
        for before, after in cases:
            assert before in source
            rejects(source.replace(before, after), panic)
            count += 1
        if panic == 'unwind':
            for before, after in (('unwind: bb7', 'unwind unreachable'), ('unwind: bb7', 'unwind continue'),
                                  ('unwind: bb7', 'unwind terminate(cleanup)'), ('unwind: bb7', 'unwind: bb9'),
                                  ('unwind: bb8', 'unwind: bb9'), ('resume;', 'return;'),
                                  ('resume;', 'unreachable;')):
                rejects(source.replace(before, after), panic)
                count += 1
    print(f'Worker MIR lifecycle: PASS; {count} owner/guard/return/unwind regressions rejected')


if __name__ == '__main__':
    main()
