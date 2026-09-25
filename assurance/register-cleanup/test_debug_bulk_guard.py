#!/usr/bin/env python3
"""Reject retained bulk-reader forwarding regressions with its producer composed."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_bulk_guard as check
from test_debug_kmac_bulk_bridge import changed as change_outer


def changed(case, body, old, new):
    outer = change_outer(case.outer, body, old, new)
    return check.Case(outer, replace(case.inner, kmac=outer.kmac, sha3=outer.sha3))


def boundaries():
    m = check.model
    machine = check.BulkGuard({}, '', {}, 0, 1, 1, None, None, 'producer')
    result = machine.allocate('4:result', 24)
    reader = machine.allocate('reader', 16)
    output = machine.allocate('output', 1, payload=True)
    machine.allocate('result', 24)
    args = [result, reader, output, 1, 0, m.UNKNOWN]
    rejected = 0
    for index, value in ((0, m.Pointer('result')), (0, output), (1, output), (2, reader),
                         (3, 0), (4, 1), (5, 8)):
        wrong = list(args)
        wrong[index] = value
        try:
            machine.run('producer', wrong)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('malformed bulk handoff accepted')
    body = 'define void @producer(ptr %r, ptr %reader, ptr %out, i64 %n, i1 %mode, i8 %v) {\nstart:\n  ret void\n}'
    machine.functions['producer'] = (m.parameters(body), m.blocks(body))
    assert machine.run('producer', args) is None and machine.producer_calls == 1 and not machine.in_producer
    try:
        machine.run('producer', args)
    except ValueError:
        rejected += 1
    else:
        raise AssertionError('duplicate bulk handoff accepted')
    assert rejected == 8
    print('Bulk handoff: one control; eight malformed/duplicate calls rejected', flush=True)


def mutants(case):
    producer, outer = check.bridge.closure(case.outer)
    for name, body in outer.items():
        if name == case.outer.root or '14squeeze_secret' in name:
            for line in body.splitlines():
                symbol = re.search(check.comparison.SYMBOL, line)
                if not symbol or not re.search(r'^\s*call void @', line):
                    continue
                if symbol[1] != producer and '14squeeze_secret' not in symbol[1]:
                    continue
                yield 'omitted handoff', changed(case, body, line, '')
                yield 'duplicated handoff', changed(case, body, line, line + '\n' + line)
                args = check.comparison.arguments(line, symbol.end())
                for index, value in ((1, args[2]), (2, 'ptr %self'), (3, 'i64 0')):
                    yield 'wrong original metadata', changed(case, body, line, line.replace(args[index], value, 1))
                if symbol[1] == producer:
                    yield 'bulk turned final', changed(case, body, 'i1 zeroext false', 'i1 zeroext true')
                    yield 'tail supplied in byte mode', changed(case, body, 'i8 undef', 'i8 7')
            pointer = '%output.0' if name == case.outer.root else '%destination.0'
            yield 'direct payload read', changed(case, body, 'start:',
                'start:\n  %leak = load i8, ptr ' + pointer + ', align 1')
        if '7map_err' in name:
            yield 'error becomes success', changed(case, body, 'store i64 2, ptr %_0', 'store i64 1, ptr %_0')
            yield 'error erased', changed(case, body, 'store i8 %_6,', 'store i8 0,')


def main(record, shard=None):
    boundaries()
    before = check.comparison.capture.sources()
    cases = list(check.cases(record))
    assert len(cases) == 16 and (shard is None or shard in range(4))
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    counts = []
    for case in chosen:
        check.inspect(case, False)
        _, original = check.bridge.closure(case.outer)
        count = 0
        for label, mutant in mutants(case):
            # Reuse only the producer oracle checked above: these mutations may
            # change outer wrappers, never the guarded producer/helper closure.
            _, _, inner = check.guard.squeeze.closure(case.inner)
            _, _, mutated_inner = check.guard.squeeze.closure(mutant.inner)
            assert inner == mutated_inner and original
            try:
                check.inspect(mutant, False, check_producer=False)
            except ValueError:
                count += 1
            else:
                raise AssertionError('accepted bulk mutation: ' + label)
        body = original[case.outer.root]
        renamed = re.sub(r'%_3\b', '%bulk_result', body)
        assert renamed != body
        check.inspect(changed(case, body, body, renamed), False, check_producer=False)
        assert count == 16
        counts.append(count)
        print(f'Composed bulk mutations: {count}; SSA control PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print(f'Bulk composition rejects {sum(counts)} regressions; {len(counts)} SSA controls PASS')
    print('Compiler/runtime subprocesses forbidden; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
