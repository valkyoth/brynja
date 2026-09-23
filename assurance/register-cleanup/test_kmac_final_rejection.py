#!/usr/bin/env python3
"""Retained constructor-rejection mutations; no compiler/runtime rerun."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_final_rejection as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, labels):
    error, cleanup, resume, terminate = labels
    block = trace.graph[error]
    for index in range(len(block) - 1):
        yield 'missing rejection operation', replace_block(function, error, block[:index] + block[index + 1:])
    yield 'wrong error field', function.replace(block[1], block[1].replace('i64 8', 'i64 16'), 1)
    yield 'wrong constructor error identity', function.replace(block[2], re.sub(r'store i8 \d+', 'store i8 0', block[2]), 1)
    yield 'success-shaped result on rejection', function.replace(block[3], block[3].replace('i64 2', 'i64 1'), 1)
    yield 'rejection returns before cleanup', replace_block(function, error, block[:4] + ['ret void'])
    yield 'rejection reaches successful copy', replace_block(function, error, block[:-1] + ['br label %' + trace.adapter_details[3]])
    for label, index in ((error, 4), (cleanup, 2)):
        lines = trace.graph[label]
        call = lines[index]
        name, args = check.forwarding.adapter.routes.guard.call(call)
        yield 'unbound cleanup', function.replace(call, call.replace(name, 'unreviewed_wipe'), 1)
        yield 'wrong owner cleanup', function.replace(call, call.replace('%self.0', '%output.0'), 1)
        yield 'cleanup call with wrong ABI', function.replace(call, call.replace('void @', 'i8 @'), 1)
        yield 'unexpected payload write', replace_block(function, label, lines[:index] + ['store i8 0, ptr %output.0, align 1'] + lines[index:])
    unwind = trace.graph[cleanup]
    yield 'unwind skips wipe', replace_block(function, cleanup, unwind[:2] + ['br label %' + resume])
    yield 'wrong exception propagated', replace_block(function, resume, ['resume { ptr, i32 } %foreign'])
    yield 'constructor unwind returns normally', replace_block(function, resume, ['ret void'])
    terminal = trace.graph[terminate]
    yield 'unknown termination call', replace_block(function, terminate, terminal[:2] + ['tail call void @unreviewed()'] + terminal[3:])
    yield 'double panic returns normally', replace_block(function, terminate, terminal[:-1] + ['ret void'])
    yield 'unwind invokes wrong landing pad', replace_block(function, 'start', trace.graph['start'][:-1] + [
        'to label %' + trace.edges['start'][0][0] + ' unwind label %' + terminate])


def main(record):
    functions = count = controls = bindings = 0
    for function, callees, constructor, code, wipes in check.cases(record):
        inspect = lambda value: check.inspect(value, callees, constructor, code, wipes)
        trace, _, labels = inspect(function)
        count += rejects(inspect, function, mutations(function, trace, labels))
        try:
            check.inspect(function, callees, constructor, code, set())
        except ValueError:
            bindings += 1
        else:
            raise AssertionError('unbound wipe accepted')
        locals_ = {match[1] for lines in trace.graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%reject_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless rejection comment\n', 1)):
            assert changed != function
            assert len(inspect(changed)[2]) == 4
            controls += 1
        functions += 1
    assert (functions, count, controls, bindings) == (16, 384, 48, 16)
    print(f'KMAC final rejection rejects {count} LLVM mutations and {bindings} missing wipe bindings; {controls} naming/comment controls across {functions} adapters PASS')
    print('Retained-text checks only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
