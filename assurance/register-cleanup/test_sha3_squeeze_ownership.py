#!/usr/bin/env python3
"""Mutation controls for squeeze initialization uses and post-write cleanup."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_squeeze_ownership as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, graph, uses, details, final):
    label, index, cleanup_index, returning = details
    lines = graph[label]
    _, params = check.adapter.routes.guard.call(lines[index])
    initialization = check.comparison.pointer(params[0])
    source = check.comparison.pointer(params[1])
    for injection in (
            f'%leak = load ptr, ptr {initialization}, align 8',
            f'store ptr null, ptr {initialization}, align 8',
            f'store ptr {initialization}, ptr %self, align 1',
            f'%escape = getelementptr inbounds nuw i8, ptr {initialization}, i64 0',
            f'%escape = getelementptr inbounds nuw i8, ptr {initialization}, i64 8',
            f'%escape = ptrtoint ptr {initialization} to i64',
            f'%escape = select i1 true, ptr {initialization}, ptr null',
            f'call void @unreviewed(ptr {initialization})',
            f'call void @llvm.memcpy.p0.p0.i64(ptr %self, ptr {initialization}, i64 24, i1 false)',
            f'%leak = load i64, ptr {initialization}, align 8'):
        yield 'forbidden descriptor access/escape', replace_block(function, 'start', [injection] + graph['start'])
    for at in range(index, len(lines)):
        yield 'omitted write/cleanup/result operation', replace_block(function, label, lines[:at] + lines[at + 1:])
    for parent, offset, call in uses:
        name, args = check.adapter.routes.guard.call(call)
        for old, new in ((name, 'unreviewed_write'), (' ' + initialization + ',', ' %self,'),
                         ('noalias ', ''), ('tail call ', 'invoke ')):
            changed = call.replace(old, new)
            yield 'unbound or foreign descriptor call', replace_block(function, parent,
                graph[parent][:offset] + [changed] + graph[parent][offset + 1:])
    call = lines[index]
    for old, new in ((' ' + source + ',', ' ' + initialization + ','), (' ' + source + ',', ' %self,')):
        yield 'descriptor or owner used as output payload', replace_block(function, label,
            lines[:index] + [call.replace(old, new)] + lines[index + 1:])
    cleanup = lines[cleanup_index]
    for old, new in (('i64 noundef 168', 'i64 noundef 1'), (' ' + source + ',', ' %self,'),
                     ('clear_owned_region', 'unreviewed_clear')):
        yield 'wrong/partial staging clearing', replace_block(function, label,
            lines[:cleanup_index] + [cleanup.replace(old, new)] + lines[cleanup_index + 1:])
    swapped = list(lines)
    swapped[index], swapped[cleanup_index] = swapped[cleanup_index], swapped[index]
    yield 'clear staging before writing instead of after', replace_block(function, label, swapped)
    yield 'inverted write result', replace_block(function, label,
        lines[:index + 1] + [lines[index + 1].replace('icmp eq', 'icmp ne')] + lines[index + 2:])
    result = graph[returning]
    phi = result[0]
    changed = re.sub(r'\[ ([^,]+), %' + re.escape(label) + r' \]', '[ 0, %' + label + ' ]', phi)
    yield 'write error identity replaced at return', replace_block(function, returning, [changed, result[1]])
    yield 'return ignores error phi', replace_block(function, returning, [phi, 'ret i8 0'])
    if final:
        yield 'tail writes too much', replace_block(function, label,
            lines[:index] + [call.replace('i64 noundef 1)', 'i64 noundef 2)')] + lines[index + 1:])
        for at, line in enumerate(lines):
            if ' = select i1 ' in line and ', i8 4' in line:
                yield 'write rejection becomes success', replace_block(function, label,
                    lines[:at] + [line.rsplit(', ', 1)[0] + ', i8 -1'] + lines[at + 1:])
    else:
        count = params[2].split()[-1]
        definition = next(line for block in graph.values() for line in block if line.startswith(count + ' = '))
        for replacement in ('i64 200)', 'i64 18446744073709551615)'):
            yield 'write exceeds original staging bound', function.replace(definition, re.sub(r'i64 (136|168)\)', replacement, definition), 1)
    yield 'initialization loses exclusive-reference contract', function.replace('dereferenceable(24)', 'dereferenceable(16)', 1)


def main(record):
    functions = count = controls = bindings = 0
    for function, write, clear, bulk, compiler in check.cases(record):
        inspect = lambda value: check.inspect(value, write, clear, bulk, compiler)
        graph, uses, details, final = inspect(function)
        count += rejects(inspect, function, mutations(function, graph, uses, details, final))
        for wrong in (('unreviewed', clear, bulk), (write, 'unreviewed', bulk), (write, clear, 'unreviewed')):
            try:
                check.inspect(function, *wrong, compiler)
            except ValueError:
                bindings += 1
            else:
                raise AssertionError('missing dependency binding accepted')
        locals_ = {match[1] for lines in graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%owned_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless ownership comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        functions += 1
    assert (functions, count, bindings, controls) == (32, 1040, 96, 96), (functions, count, bindings, controls)
    print(f'Squeeze ownership rejects {count} LLVM mutations and {bindings} missing dependency bindings; {controls} controls across {functions} bodies PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
