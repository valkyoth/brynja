#!/usr/bin/env python3
"""Reject consuming-reader handoff/cleanup regressions in retained LLVM."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_consuming_final as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def boundaries():
    m = check.model
    machine = check.ConsumingFinal({}, '', {}, 0, 1, 7, 1, 'producer', 'constructor')
    storage = machine.allocate('storage', 1040, payload=True)
    output = machine.allocate('output', 1, payload=True)
    reader = machine.allocate('4:reader', 16)
    result = machine.allocate('4:result', 24)
    machine.fields(reader, [(0, 8, storage), (8, 1, 1)])
    args = [result, reader, output, 1, 1, 7]
    rejected = 0

    def reject(call):
        try:
            call()
        except ValueError:
            return 1
        raise AssertionError('malformed consuming-model boundary accepted')

    rejected += reject(lambda: machine.load(m.Pointer('reader', 8), 1))
    for index, value in ((0, output), (1, storage), (2, storage), (3, 0), (4, 0), (5, 8)):
        wrong = list(args)
        wrong[index] = value
        rejected += reject(lambda: machine.run('producer', wrong))
    # A minimal actual helper exercises address binding, not the crypto body.
    body = 'define void @producer(ptr %r, ptr %reader, ptr %out, i64 %n, i1 %mode, i8 %v) {\nstart:\n  ret void\n}'
    machine.functions['producer'] = (m.parameters(body), m.blocks(body))
    assert machine.run('producer', args) is None and machine.producer_calls == 1 and not machine.in_producer
    rejected += reject(lambda: machine.run('producer', args))
    rejected += reject(lambda: machine.load(m.Pointer('reader', 8), 1))
    machine.in_producer = True
    assert machine.load(m.Pointer('reader'), 8) == storage
    assert machine.load(m.Pointer('reader', 8), 1) == 1
    machine.store(m.Pointer(reader.region, 8), 1, 0)
    assert machine.load(m.Pointer('reader', 8), 1) == 0
    rejected += reject(lambda: machine.load(m.Pointer('reader', 7), 1))
    rejected += reject(lambda: machine.load(m.Pointer('reader', 8), 8))
    assert rejected == 11 and 'reader' not in machine.sizes
    print('Consuming address binding: 4 controls; 11 malformed/inactive calls rejected', flush=True)


def mutants(case):
    producer, _, _, outer = check.bridge.closure(case)
    roots = [case.root] + [name for name in outer if '25squeeze_final_bits_secret' in name]
    assert len(roots) == 2
    for name in roots:
        body = outer[name]
        for label, lines in check.model.blocks(body).items():
            for index, line in enumerate(lines):
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and re.search(r'\b(?:call|invoke) ', line):
                    callee = symbol[1]
                    destructor = 'drop_in_place' in callee or 'drop_glue' in callee
                    if callee == producer:
                        for old, new in (('i1 zeroext true', 'i1 zeroext false'), ('i8 %valid', 'i8 0'),
                                         ('i64 %destination.1', 'i64 0')):
                            assert old in line
                            new_lines = lines[:index] + [line.replace(old, new)] + lines[index + 1:]
                            yield 'wrong producer metadata', changed(case, body, replace_block(body, label, new_lines))
                    if destructor or callee == producer:
                        if 'invoke ' in line:
                            edge = re.fullmatch(r'to label %(\S+) unwind label %(\S+)', lines[index + 1])
                            assert edge
                            new_lines = lines[:index] + ['br label %' + edge[1]] + lines[index + 2:]
                        else:
                            new_lines = lines[:index] + lines[index + 1:]
                        yield 'omitted producer/destructor', changed(case, body, replace_block(body, label, new_lines))
                if line.startswith('resume { ptr, i32 }'):
                    yield 'swallowed consuming unwind', changed(case, body,
                        replace_block(body, label, lines[:index] + ['ret void'] + lines[index + 1:]))
    body = outer[case.root]
    for pointer in ('%self.0', '%output.0'):
        yield 'direct secret read', changed(case, body, body.replace('start:',
            'start:\n  %disclose = load i8, ptr ' + pointer + ', align 1', 1))


def main(record, shard=None):
    boundaries()
    before = check.comparison.capture.sources()
    cases = list(check.bridge.cases(record))
    assert len(cases) == 16 and (shard is None or shard in range(4))
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    counts = []
    for case in chosen:
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        body = check.comparison.definitions(case.kmac)[case.root]
        renamed = re.sub(r'%_12\b', '%consuming_drop_guard', body)
        assert renamed != body
        check.inspect(changed(case, body, renamed), False)
        print('Consuming mutations: ' + str(counts[-1]) + '; SSA control PASS', flush=True)
    assert min(counts) >= 10 and before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print(f'Consuming final rejects {sum(counts)} regressions; {len(counts)} SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Compiler/runtime subprocesses forbidden; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
