#!/usr/bin/env python3
"""Retained final-reader cleanup/forwarding mutations; no crypto execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_final_reader as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, graph, labels):
    normal, cleanup, resume, terminate = labels
    header = function.splitlines()[0]
    for old, new in (('sret([24 x i8])', 'sret([32 x i8])'), ('define void @', 'define i64 @')):
        yield 'reader ABI', function.replace(header, header.replace(old, new), 1)
    start = graph['start']
    invocation = start[-2]
    name, args = check.adapter.routes.guard.call(invocation)
    yield 'unbound secret callee', function.replace(invocation, invocation.replace(name, 'unreviewed_secret'), 1)
    for index in range(6):
        if index in (0, 1, 2):
            pointer = check.comparison.pointer(args[index])
            replacement = args[index].replace(pointer, '%foreign')
        elif index == 4:
            replacement = args[index].replace('true', 'false')
        else:
            replacement = re.sub(check.SSA + '$', '%foreign', args[index])
        yield 'wrong secret argument', function.replace(invocation, invocation.replace(args[index], replacement, 1), 1)
    for index, line in enumerate(start[:-2]):
        if ' = alloca ' in line:
            yield 'wrong handle width', function.replace(line, line.replace('[16 x i8]', '[8 x i8]'), 1)
        elif line.startswith('store '):
            yield 'missing original handle field', replace_block(function, 'start', start[:index] + start[index + 1:])
            yield 'duplicate handle field', replace_block(function, 'start', start[:index] + [line] + start[index:])
            value = re.search(r'store (?:ptr|i8) (' + check.SSA + ')', line)[1]
            yield 'substituted owner/lifecycle field', function.replace(line, line.replace(value, '%foreign', 1), 1)
        elif ' = getelementptr ' in line:
            offset = int(line.rsplit(' ', 1)[1])
            yield 'wrong handle/output field offset', function.replace(line, line.rsplit(' ', 1)[0] + ' ' + str(offset + 1), 1)
    yield 'callee bypasses normal cleanup', replace_block(function, 'start', start[:-1] + [f'to label %{resume} unwind label %{cleanup}'])
    for label in (normal, cleanup):
        lines = graph[label]
        call_index = 1 if label == normal else 3
        call = lines[call_index]
        name, args = check.adapter.routes.guard.call(call)
        pointer = check.comparison.pointer(args[0])
        yield 'cleanup callee removed/replaced', function.replace(call, call.replace(name, 'unreviewed_wipe'), 1)
        yield 'cleanup receives wrong owner', function.replace(call, call.replace(pointer, '%foreign'), 1)
        load_index = call_index - 1
        load = lines[load_index]
        yield 'cleanup reloads wrong handle', function.replace(load, re.sub(r'ptr ' + check.SSA, 'ptr %foreign', load), 1)
        yield 'cleanup bypass', replace_block(function, label, ['ret void'] if label == normal else lines[:2] + ['br label %' + resume])
        yield 'unexpected cleanup output write', replace_block(function, label, lines[:call_index] + ['store i64 0, ptr %_0, align 8'] + lines[call_index:])
    yield 'wrong resumed exception', replace_block(function, resume, ['resume { ptr, i32 } %foreign'])
    yield 'swallowed original exception', replace_block(function, resume, ['ret void'])
    terminal = graph[terminate]
    yield 'unidentified double panic', replace_block(function, terminate, terminal[:2] + ['call void @unreviewed()'] + terminal[3:])
    yield 'double panic returns', replace_block(function, terminate, terminal[:-1] + ['ret void'])
    yield 'unknown pre-reader work', replace_block(function, 'start', start[:1] + ['call void @unreviewed()'] + start[1:])


def main(record):
    count = controls = functions = bindings = 0
    for function, definitions, wipes in check.cases(record):
        inspect = lambda value: check.inspect(value, definitions, wipes)
        graph, labels, secret = inspect(function)
        count += rejects(inspect, function, mutations(function, graph, labels))
        for changed, changed_wipes in (({key: value for key, value in definitions.items() if key != secret}, wipes),
                                      (dict(definitions, **{secret: definitions[secret].replace('define internal fastcc void @', 'define internal void @', 1)}), wipes),
                                      (definitions, set())):
            try:
                check.inspect(function, changed, changed_wipes)
            except ValueError:
                bindings += 1
            else:
                raise AssertionError('missing or ABI-incompatible callee binding accepted')
        local_names = {match[1] for lines in graph.values() for line in lines
                       if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%reader_' + m[0][1:] if m[0] in local_names else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless final-reader comment\n', 1)):
            assert changed != function
            assert len(inspect(changed)[0]) == 5
            controls += 1
        functions += 1
    assert (functions, count, controls, bindings) == (16, 560, 48, 48)
    print(f'Portable final reader rejects {count} LLVM mutations and {bindings} callee-binding regressions; {controls} naming/comment controls across {functions} bodies PASS')
    print('Retained-text checks only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
