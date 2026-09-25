#!/usr/bin/env python3
"""Reject retained consuming/fill handoff and cleanup regressions."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_filled_consuming as check
import test_debug_consuming_final as outer_test
import test_debug_filled_final as inner_test
from test_debug_portable_final_bridge import changed


def boundaries(case):
    m = check.model
    _, _, names, _ = check.closure(case)
    machine = check.FilledConsuming({}, '', names, 0, 1, 7, 1, 'producer', 'constructor', None, None, names['rate'], None)
    storage = machine.allocate('storage', 1040, payload=True)
    output = machine.allocate('output', 1, payload=True)
    reader = machine.allocate('4:reader', 16)
    result = machine.allocate('4:result', 24)
    machine.fields(reader, [(0, 8, storage), (8, 1, 1)])
    machine.initializer = machine.allocate('4:initializer', 24)
    machine.fields(machine.initializer, [(0, 8, output), (8, 8, 1), (16, 8, 0)])
    args = [result, reader, output, 1, 1, 7]
    rejected = 0

    def reject(call):
        try:
            call()
        except ValueError:
            return 1
        raise AssertionError('malformed filled-consuming boundary accepted')

    rejected += reject(lambda: machine.load(m.Pointer('reader', 8), 1))
    for index, value in ((0, output), (1, storage), (2, storage), (3, 0), (4, 0), (5, 8)):
        wrong = list(args)
        wrong[index] = value
        rejected += reject(lambda: machine.run('producer', wrong))
    body = 'define void @producer(ptr %r, ptr %reader, ptr %out, i64 %n, i1 %mode, i8 %v) {\nstart:\n  ret void\n}'
    machine.functions['producer'] = (m.parameters(body), m.blocks(body))
    assert machine.run('producer', args) is None and machine.producer_calls == 1 and not machine.in_producer
    rejected += reject(lambda: machine.run('producer', args))
    rejected += reject(lambda: machine.load(m.Pointer('reader', 8), 1))
    rejected += reject(lambda: machine.run(names['fill'], [storage, 1]))
    machine.in_producer = True
    assert machine.load(m.Pointer('reader'), 8) == storage
    assert machine.load(m.Pointer('reader', 8), 1) == 1
    rejected += reject(lambda: machine.run(names['fill'], [storage, 1]))
    machine.in_squeeze = True
    rejected += reject(lambda: machine.run(names['fill'], [storage, 1]))
    machine.store(m.Pointer(reader.region, 8), 1, 0)
    assert machine.load(m.Pointer('reader', 8), 1) == 0
    rejected += reject(lambda: machine.load(m.Pointer('reader', 7), 1))
    rejected += reject(lambda: machine.load(m.Pointer('reader', 8), 8))
    rejected += reject(lambda: machine.load(m.Pointer('storage', 1039), 1))
    rejected += reject(lambda: machine.store(m.Pointer('storage', 1039), 1, 0))
    for bad in ([reader, 1], [storage, 0], [storage, names['rate'] + 1]):
        rejected += reject(lambda: machine.run(names['fill'], bad))
    machine.in_fill = True
    rejected += reject(lambda: machine.run(names['fill'], [storage, 1]))
    rejected += reject(lambda: machine.load(storage, 1))
    assert machine.load(m.Pointer('storage', 1039), 1) == names['rate']
    machine.store(m.Pointer('storage', 1039), 1, 0)
    assert machine.cursor == 0 and 'reader' not in machine.sizes and rejected == 21
    print('Filled consuming binding: six controls; twenty-one malformed/inactive calls rejected', flush=True)


def mutants(case):
    yield from outer_test.mutants(case)
    yield from inner_test.mutants(case)


def main(record, shard=None):
    before = check.comparison.capture.sources()
    cases = list(check.consuming.bridge.cases(record))
    assert len(cases) == 16 and (shard is None or shard in range(4))
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    boundaries(chosen[0])
    counts = []
    for case in chosen:
        check.inspect(case, False)
        count = 0
        for label, mutant in mutants(case):
            try:
                check.inspect(mutant, False)
            except ValueError:
                count += 1
            else:
                raise AssertionError('accepted filled-consuming regression: ' + label)
        body = check.comparison.definitions(case.kmac)[case.root]
        renamed = re.sub(r'%_12\b', '%consuming_drop_guard', body)
        assert renamed != body
        check.inspect(changed(case, body, renamed), False)
        assert count >= 39
        counts.append(count)
        print(f'Filled consuming mutations: {count}; SSA control PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print(f'Filled consuming rejects {sum(counts)} regressions; {len(counts)} SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Compiler/runtime subprocesses forbidden; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
