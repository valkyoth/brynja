#!/usr/bin/env python3
"""Retained bulk-loop progress, error and premature-commit mutation controls."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_squeeze_progress as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, labels, exits):
    preheader, setup, head, progress, returning = labels
    writing, commit = exits
    graph = trace.graph
    for label in labels:
        for index, line in enumerate(graph[label]):
            yield 'missing loop operation', replace_block(function, label, graph[label][:index] + graph[label][index + 1:])
            variants = []
            if ' = phi i64 ' in line:
                variants += [('wrong initial remainder', re.sub(r'\[ %[^,]+,', '[ 0,', line, count=1)),
                             ('lost loop-carried progress', re.sub(r'(\], \[ )%[^,]+', r'\g<1>0', line))]
            if '@llvm.umin.i64' in line:
                variants += [('unbounded chunk maximum', line.replace('llvm.umin', 'llvm.umax')),
                             ('zero-sized chunk', re.sub(r'i64 (136|168)\)', 'i64 0)', line)),
                             ('oversized chunk', re.sub(r'i64 (136|168)\)', 'i64 169)', line))]
            if '12fill_staging' in line:
                name, args = check.adapter.routes.guard.call(line)
                variants += [('unbound fill', line.replace(name, 'unreviewed_fill')),
                             ('fill foreign owner', line.replace(' %self,', ' %initialization,')),
                             ('fill wrong chunk', line.replace(args[1], 'i64 noundef 0'))]
            if ' = sub nuw ' in line:
                operands = re.search('sub nuw i64 (' + check.SSA + '), (' + check.SSA + ')', line)
                variants += [('no remaining progress', line.replace(', ' + operands[2], ', 0')),
                             ('subtract whole remainder', line.replace(', ' + operands[2], ', ' + operands[1])),
                             ('increasing remainder', line.replace('sub nuw', 'add'))]
            if ' = icmp ' in line:
                variants.append(('wrong loop/status comparison', line.replace('icmp eq', 'icmp ne').replace('icmp ugt', 'icmp uge')))
            if line.startswith('br i1 '):
                flag, yes, no = check.adapter.shape.branch(trace, label)
                variants.append(('inverted loop edge', f'br i1 {flag}, label %{no}, label %{yes}'))
            for reason, changed in variants:
                yield reason, replace_block(function, label, graph[label][:index] + [changed] + graph[label][index + 1:])
    result = graph[returning]
    phi = result[0]
    for predecessor in ('start', commit, head, writing):
        changed = re.sub(r'\[ ([^,]+), %' + re.escape(predecessor) + r' \]', '[ 0, %' + predecessor + ' ]', phi)
        yield 'wrong returned status for loop edge', replace_block(function, returning, [changed, result[1]])
    yield 'return ignores selected result', replace_block(function, returning, [phi, 'ret i8 0'])
    for parent in (head, writing):
        flag, yes, _ = check.adapter.shape.branch(trace, parent)
        yield 'error prematurely commits counter', replace_block(function, parent,
            graph[parent][:-1] + [f'br i1 {flag}, label %{yes}, label %{commit}'])
    _, params = check.adapter.routes.guard.call(graph[writing][0])
    yield 'write length differs from filled chunk', replace_block(function, writing,
        [graph[writing][0].replace(params[2], 'i64 noundef 1')] + graph[writing][1:])
    yield 'counter store before successful completion', replace_block(function, 'start',
        ['store i8 0, ptr %self, align 1'] + graph['start'])
    yield 'counter commit returns into loop', replace_block(function, commit,
        graph[commit][:-1] + ['br label %' + head])


def main(record):
    functions = count = bindings = controls = 0
    for function, *arguments in check.cases(record):
        inspect = lambda value: check.inspect(value, *arguments)
        trace, labels, exits, rate = inspect(function)
        count += rejects(inspect, function, mutations(function, trace, labels, exits))
        try:
            check.inspect(function, *arguments[:-1], 'unreviewed_fill')
        except ValueError:
            bindings += 1
        else:
            raise AssertionError('missing actual fill binding accepted')
        locals_ = {match[1] for lines in trace.graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%loop_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless progress comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        # Mathematical boundary checks for the structurally matched operations;
        # this is not execution of the LLVM or a full counter-width proof.
        for remaining in (1, rate - 1, rate, rate + 1, 2 * rate, 2 * rate + 1, (1 << 64) - 1):
            chunk = min(remaining, rate)
            after = remaining - chunk
            assert 0 < chunk <= rate and 0 <= after < remaining
            assert (remaining > rate) == (after != 0)
        functions += 1
    assert (functions, count, bindings, controls) == (16, 656, 16, 48), (functions, count, bindings, controls)
    print(f'Bulk squeeze progress rejects {count} LLVM mutations and {bindings} missing fill bindings; {controls} controls across {functions} bodies PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
