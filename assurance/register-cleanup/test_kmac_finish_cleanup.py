#!/usr/bin/env python3
"""Retained finish/Core metadata cleanup regressions, without subprocesses."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_finish_cleanup as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def selected(function, core):
    graph, edges, _ = check.graph_info(function)
    starts = ['start'] if core else sum((list(values) for values in check.errors(function)), [])
    pending, seen = list(starts), set()
    while pending:
        label = pending.pop()
        if label in seen:
            continue
        seen.add(label)
        pending.extend(edges[label][0])
    return graph, edges, seen


def mutants(function, names, state_callees, core=False):
    graph, edges, seen = selected(function, core)
    owner = '%_1' if core else '%self'
    for label in sorted(seen):
        lines = graph[label]
        for index, line in enumerate(lines):
            if not re.match(r'(?:' + check.SSA + r' = )?(?:tail )?(?:call|invoke) ', line):
                continue
            name, args = check.guard.call(line)
            role = next((role for role in ('CLEAR', 'GLUE', 'CORE') if names.get(role) == name), None)
            if role is not None:
                yield 'unbound cleanup identity', function.replace(line, line.replace('@' + name + '(', '@unreviewed('), 1)
                pointer = check.comparison.pointer(args[0])
                yield 'wrong cleanup owner', function.replace(line, line.replace(pointer, '%foreign'), 1)
                if role == 'CLEAR':
                    for width in (0, 2, 63, 67):
                        yield 'wrong cleanup width', function.replace(line, line.replace(args[1], f'i64 noundef {width}'), 1)
                    yield 'wrong clearing ABI', function.replace(line, line.replace('noundef i8 ', 'noundef i32 '), 1)
                else:
                    yield 'wrong destructor ABI', function.replace(line, line.replace('fastcc void ', 'void '), 1)
                if 'invoke ' in line:
                    normal, unwind = edges[label][0]
                    yield 'skip destructor invocation', replace_block(function, label, lines[:index] + ['br label %' + normal])
                    yield 'exchange destructor edges', replace_block(function, label,
                        lines[:-1] + ['to label %' + unwind + ' unwind label %' + normal])
                else:
                    yield 'skip metadata region', replace_block(function, label, lines[:index] + lines[index + 1:])
                duplicate = line.replace('invoke ', 'call ')
                duplicate = re.sub('^' + check.SSA + ' = ', '%duplicate_request = ', duplicate)
                yield 'duplicate cleanup', replace_block(function, label, lines[:index] + [duplicate] + lines[index:])
            elif name in state_callees:
                pointer = check.comparison.pointer(args[0])
                yield 'wrong state owner', function.replace(line, line.replace(pointer, '%foreign'), 1)
                yield 'unbound state call', function.replace(line, line.replace('@' + name + '(', '@unreviewed('), 1)
            elif name in (names.get('FRAMING'), names.get('PACKER')):
                yield 'wrong framing owner', function.replace(line, line.replace('%storage.i', '%foreign'), 1)
                yield 'unbound framing call', function.replace(line, line.replace('@' + name + '(', '@unreviewed('), 1)
        for line in lines:
            if re.fullmatch(check.SSA + r' = load ptr, ptr ' + re.escape(owner) + r', align 8', line):
                yield 'wrong source metadata descriptor', function.replace(line, line.replace(owner + ',', '%foreign,'), 1)
        yield 'unreviewed owner overwrite', replace_block(function, label,
            [f'store ptr %foreign, ptr {owner}, align 8'] + lines)
        yield 'indirect side effect', replace_block(function, label,
            [f'call void %unreviewed(ptr {owner})'] + lines)
    # Error-root bypasses must not be accepted merely because the expected
    # clearing instructions survive elsewhere in the same function.
    roots = ['start'] if core else check.errors(function)[0]
    returns = [label for label, (_, terminal) in edges.items() if terminal == 'return']
    resumes = [label for label, (_, terminal) in edges.items() if terminal == 'resume']
    assert len(returns) == len(resumes) == 1
    for label in roots:
        lines = graph[label]
        for end in ('ret void', 'resume { ptr, i32 } undef', 'unreachable', 'br label %' + label,
                    'br label %' + returns[0], 'br label %' + resumes[0]):
            yield 'error bypasses cleanup or loops', replace_block(function, label, lines[:-1] + [end])
    if not core:
        _, _, origin = check.graph_info(function)
        for label in roots:
            lines = graph[label]
            for line in lines:
                match = re.fullmatch(r'store (i8 2|ptr null), ptr (' + check.SSA + r'), align 8', line)
                if match and origin(match[2])[0] == '%_0':
                    yield 'missing error discriminant', function.replace(line, '', 1)
                    replacement = 'i8 1' if match[1] == 'i8 2' else 'ptr %foreign'
                    yield 'changed error discriminant', function.replace(line, line.replace(match[1], replacement), 1)
        for label, lines in graph.items():
            if lines[-1].startswith('to label '):
                normal, unwind = edges[label][0]
                for target in returns + resumes:
                    yield 'explicit unwind bypass', replace_block(function, label,
                        lines[:-1] + ['to label %' + normal + ' unwind label %' + target])


def main(record):
    finish_count = core_count = controls = pairs = 0
    for _, function, core_function, names, state_callees in check.cases(record):
        inspect_finish = lambda value: check.inspect(value, core_function, names, state_callees)
        inspect_core = lambda value: check.inspect(function, value, names, state_callees)
        finish_count += rejects(inspect_finish, function, mutants(function, names, state_callees))
        core_count += rejects(inspect_core, core_function, mutants(core_function, names, state_callees, True))
        for original, inspect in ((function, inspect_finish), (core_function, inspect_core)):
            baseline = inspect(original)
            for changed in (
                    re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), original),
                    original.replace('start:\n', 'start:\n; harmless finish qualification comment\n', 1)):
                assert changed != original and inspect(changed) == baseline
                controls += 1
        pairs += 1
    assert (pairs, finish_count, core_count, controls) == (24, 3816, 1320, 96)
    print(f'KMAC finish cleanup rejects {finish_count} finish-path and {core_count} Core-destructor mutations; {controls} label/comment controls across {pairs} pairs PASS')
    print('Retained LLVM-text mutations only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
