#!/usr/bin/env python3
"""Retest outer bulk/consuming mutations with actual accelerated operations linked."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_accelerated_bridges as check
import test_debug_kmac_bulk_bridge as bulk_tests
import test_debug_kmac_final_bridge as final_tests


def mutants(case, consuming):
    if consuming:
        yield from final_tests.mutants(case)
    else:
        for label, mutant in bulk_tests.mutants(check.bulk_case(case)):
            yield label, replace(case, kmac=mutant.kmac, sha3=mutant.sha3)


def boundary_fixture(consuming):
    m = check.model
    machine = check.BridgedOperation({}, '', {'guard': 'guard'}, 1, int(consuming), 7 if consuming else m.UNKNOWN, None, 'producer')
    result = machine.allocate('local-result', 24)
    reader = machine.allocate('local-reader' if consuming else 'entry-reader', 8)
    storage = machine.allocate('storage', 1088, payload=True)
    output = machine.allocate('output', 1, payload=True)
    machine.allocate('result', 24)
    machine.fields(reader, [(0, 8, storage)])
    args = [result, reader, output, 1, int(consuming), 7 if consuming else m.UNKNOWN]
    body = 'define void @producer(ptr %r, ptr %reader, ptr %out, i64 %n, i1 %mode, i8 %v) {\nstart:\n  ret void\n}'
    machine.functions['producer'] = (m.parameters(body), m.blocks(body))
    return machine, args


def boundaries():
    m = check.model
    count = 0
    for consuming in (False, True):
        for index, value in ((0, m.Pointer('result')), (0, m.Pointer('output')), (1, m.Pointer('output')),
                             (1, 0), (2, m.Pointer('storage')), (3, 0), (4, int(not consuming)), (5, 0)):
            machine, args = boundary_fixture(consuming)
            args[index] = value
            try:
                machine.run('producer', args)
            except ValueError:
                count += 1
            else:
                raise AssertionError('malformed producer handoff accepted')
        machine, args = boundary_fixture(consuming)
        assert machine.run('producer', args) is None and machine.producer_calls == 1 and not machine.in_producer
        for action in (lambda: machine.run('producer', args),
                       lambda: machine.run('guard', [args[0], args[1], args[0]])):
            try:
                action()
            except ValueError:
                count += 1
            else:
                raise AssertionError('repeated or inactive handoff accepted')
    assert count == 20
    print('Bridge bindings: two controls; twenty malformed/repeated/inactive handoffs rejected', flush=True)


def main(record, shard):
    boundaries()
    before = check.comparison.capture.sources()
    cases = list(check.operation.cases(record))
    assert len(cases) == 8
    for case in cases if shard is None else [cases[shard]]:
        for consuming in (False, True):
            baseline = check.inspect(case, False, consuming)[0]
            count = 0
            for label, mutant in mutants(case, consuming):
                try:
                    check.inspect(mutant, False, consuming)
                except ValueError:
                    count += 1
                else:
                    raise AssertionError('accepted composed bridge regression: ' + label)
            root = case.root if consuming else check.bulk_case(case).root
            body = check.comparison.definitions(case.kmac)[root]
            for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M),
                            re.sub(r'%_4\b' if consuming else r'%_3\b', '%bridge_result', body)):
                assert control != body
                assert check.inspect(replace(case, kmac=case.kmac.replace(body, control)), False, consuming)[0] == baseline
            assert count == ((86 if case.compiler == '1.90.0' else 85) if consuming else 41)
            print(f'Accelerated {"consuming" if consuming else "bulk"} composition rejects {count} mutations; two controls PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 8 paths, both bridges' if shard is None else f'shard {shard}/8; both bridges; all eight required'))
    print('Compiler/runtime subprocesses forbidden; engine/primitive bodies opaque; no whole-call erasure claim')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
