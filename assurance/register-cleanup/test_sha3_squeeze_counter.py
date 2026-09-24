#!/usr/bin/env python3
"""Mutate actual retained bulk counter arithmetic, layout and byte encoding."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_squeeze_counter as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, commit):
    for label in ('start', commit):
        lines = trace.graph[label]
        for index, line in enumerate(lines):
            yield 'missing counter instruction', replace_block(function, label, lines[:index] + lines[index + 1:])
            variants = []
            if 'getelementptr ' in line:
                variants.append(('wrong counter field', re.sub(r'i64 \d+$', 'i64 32', line)))
            if ' = load i64, ' in line:
                variants.append(('truncated low counter word', line.replace('load i64,', 'load i8,')))
            if ' = load ' in line:
                variants.append(('unsupported counter load alignment', line.replace('align 1', 'align 64')))
            if ' = shl ' in line:
                variants.append(('wrong decoded byte significance', re.sub(r', \d+$', ', 0', line)))
                if line.endswith(', 120'):
                    variants.append(('poison upper counter bit', line.replace('shl nuw', 'shl nuw nsw')))
            if ' = or ' in line:
                variants.append(('lost decoded fragment', re.sub(r', ' + check.SSA + '$', ', 0', line)))
            if ' = add' in line:
                variants += [('sum replaced with xor', line.replace('add nuw', 'xor').replace('add i128', 'xor i128')),
                             ('request omitted from sum', re.sub(r', ' + check.SSA + '$', ', 0', line))]
            if ' = icmp ult i128' in line:
                variants.append(('wrong overflow comparison', line.replace('icmp ult', 'icmp eq')))
            if 'extractvalue { i128, i1 }' in line:
                variants.append(('wrong overflow result', line.replace(', 1', ', 0')))
            if '@llvm.uadd.with.overflow' in line:
                variants.append(('overflow checks wrong request', re.sub(r', i128 ' + check.SSA + r'\)', ', i128 0)', line)))
            if ' = select i1 ' in line:
                variants.append(('counter result poisoned on success', re.sub(r', i128 ' + check.SSA + '$', ', i128 poison', line)))
            if ' = lshr i128 ' in line:
                variants.append(('wrong second encoded byte', line.replace(', 8', ', 7')))
            if ' = lshr <' in line:
                shifts = list(re.finditer(r'i128 (\d+)', line))
                for match in shifts:
                    shift = int(match[1])
                    changed = line[:match.start(1)] + str((shift + 1) % 128) + line[match.end(1):]
                    variants.append(('wrong encoded lane significance', changed))
            if ' = insertelement ' in line:
                variants.append(('zeroed encoding source', re.sub(r', i128 ' + check.SSA + ',', ', i128 0,', line)))
            if ' = shufflevector ' in line:
                variants.append(('all encoding lanes poisoned', re.sub(r'<\d+ x i32> .+$', lambda m: m[0].split('>')[0] + '> poison', line)))
            if line.startswith('store '):
                variants += [('wrong serialized counter address', re.sub('ptr ' + check.SSA + ',', 'ptr %self,', line)),
                             ('all committed bytes poisoned', re.sub(r'<16 x i8> ' + check.SSA, '<16 x i8> poison', line)),
                             ('wrong counter alignment', line.replace('align 1', 'align 32'))]
            if line.startswith('br i1 '):
                condition, yes, no = check.progress.adapter.shape.branch(trace, label)
                variants.append(('inverted overflow admission', f'br i1 {condition}, label %{no}, label %{yes}'))
            for reason, changed in variants:
                yield reason, replace_block(function, label, lines[:index] + [changed] + lines[index + 1:])


def poison_controls():
    """Unused nuw overflow may be poison; branch/store use must never accept it."""
    graph = {
        'start': ['%counter = getelementptr inbounds nuw i8, ptr %self, i64 16',
                  '%overflow = add nuw i128 ' + str(check.MAX) + ', 1',
                  '%selected = select i1 %condition, i128 7, i128 %overflow',
                  '%v = insertelement <16 x i128> poison, i128 %selected, i64 0',
                  '%all = shufflevector <16 x i128> %v, <16 x i128> poison, <16 x i32> zeroinitializer',
                  '%bytes = trunc <16 x i128> %all to <16 x i8>',
                  'store <16 x i8> %bytes, ptr %counter, align 1', 'ret i8 %status']}
    def evaluate(condition):
        state = dict(counter=0, writes=[])
        result = check.model.evaluate(graph, 'start', None, {'%condition': condition, '%status': 5}, state,
                                      None, dict(error=None, loop=None), True, portable_bulk=True)
        return result, state['writes']
    assert evaluate(1) == (('return', 5), [int.from_bytes(bytes([7] * 16), 'little')])
    for condition in (0, None):
        try:
            evaluate(condition)
        except ValueError:
            pass
        else:
            raise AssertionError('observable arithmetic poison accepted')


def main(record):
    counts = []
    controls = 0
    poison_controls()
    for function, *arguments in check.progress.cases(record):
        trace, _, (_, commit), _ = check.progress.inspect(function, *arguments)
        check.inspect(function, *arguments)
        inspect = lambda value: check.inspect(value, *arguments, thorough=False)
        counts.append(rejects(inspect, function, mutations(function, trace, commit)))
        locals_ = {match[1] for lines in trace.graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%counter_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless counter comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        if arguments[3] == '1.90.0':
            # Wrapping add computes the same admitted sum; overflow is separately
            # rejected by the intrinsic. Removing nuw here is a valid control.
            changed = function.replace(' = add nuw i128 ', ' = add i128 ')
            assert changed != function
            check.inspect(changed, *arguments)
            controls += 1
    assert counts == [140] * 8 + [114] * 8 and controls == 56, (counts, controls)
    print(f'Bulk squeeze counters reject {sum(counts)} retained-LLVM mutations; {controls} controls across 16 bodies PASS; per-body counts={counts}')
    print('Selected/unselected poison controls PASS; subprocess execution forbidden; no release-gate change')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
