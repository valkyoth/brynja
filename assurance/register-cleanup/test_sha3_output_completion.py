#!/usr/bin/env python3
"""Retained output-completion mutations; never compile or run Rust."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_output_completion as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, labels, values, error_exit):
    initialization, result, pointer, length = values
    graph = trace.graph
    for label in labels:
        block = graph[label]
        for index, line in enumerate(block):
            if 'llvm.experimental.noalias.scope.decl' in line:
                continue
            yield 'omitted completion instruction', replace_block(function, label, block[:index] + block[index + 1:])
            variants = []
            if ' = getelementptr ' in line:
                variants.append(('wrong descriptor field', re.sub(r'i64 (8|16)$', 'i64 0', line)))
            if ' = load ' in line:
                variants.append(('foreign descriptor load', re.sub(r'ptr %[^,]+', 'ptr %self', line)))
            if line.startswith('br i1 '):
                condition, yes, no = check.adapter.shape.branch(trace, label)
                variants.append(('swapped completion decision', f'br i1 {condition}, label %{no}, label %{yes}'))
            if line.startswith('store '):
                variants.append(('foreign result destination', re.sub(r', ptr %[^,]+', ', ptr %self', line)))
                if re.match(r'store (i8|i64) [0124],', line):
                    variants.append(('wrong result/lifecycle discriminator', re.sub(r'^(store (?:i8|i64)) [0124],', r'\g<1> 7,', line)))
                if pointer + ',' in line:
                    variants.append(('wrong output pointer', line.replace(pointer + ',', 'null,')))
                if length + ',' in line:
                    variants.append(('truncated output extent', line.replace(length + ',', '0,')))
            if ' = phi ' in line:
                if re.search(r'\[ %[^,]+,', line):
                    variants.append(('lost owned result at merge', re.sub(r'\[ (%[^,]+),', '[ undef,', line)))
                if 'phi i64 [ 0,' in line:
                    variants.append(('empty output falsely owned', line.replace('[ 0,', '[ 1,')))
            if '@llvm.memcpy.' in line:
                variants += [('partial initialization transfer', line.replace('i64 24', 'i64 16')),
                             ('foreign initialization transfer', re.sub(r'(, ptr [^%]+)%[^,]+', r'\1%self', line))]
            if 'invoke void @' in line:
                name, args = check.adapter.routes.guard.call(line)
                variants += [('unbound completion callee', line.replace(name, 'unreviewed_finish')),
                             ('foreign finish ownership', line.replace(' ' + initialization + ')', ' %self)')),
                             ('wrong finish result size', line.replace('sret([24 x i8])', 'sret([16 x i8])'))]
            for reason, changed in variants:
                if changed == line:
                    raise AssertionError('ineffective mutation: ' + reason)
                yield reason, replace_block(function, label, block[:index] + [changed] + block[index + 1:])
        yield 'extra payload store during completion', replace_block(function, label,
            ['store i8 0, ptr %destination.0, align 1'] + block)
    start, owned, decision, rejected, accepted = labels[:5]
    yield 'completion failure returns success', replace_block(function, rejected, ['br label %' + accepted])
    yield 'successful completion bypasses owned descriptor', replace_block(function, accepted, ['br label %' + error_exit])


def main(record):
    functions = count = controls = bindings = 0
    for function, *arguments in check.cases(record):
        inspect = lambda value: check.inspect(value, *arguments)
        trace, labels, values, _ = inspect(function)
        error_exit = check.errors.inspect(function, *arguments[:-1])[1][5]
        count += rejects(inspect, function, mutations(function, trace, labels, values, error_exit))
        try:
            check.inspect(function, *arguments[:-1], 'unreviewed_finish')
        except ValueError:
            bindings += 1
        else:
            raise AssertionError('unbound completion accepted')
        locals_ = {match[1] for lines in trace.graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))} - {'%valid', '%length'}
        for changed in (
                re.sub(check.SSA, lambda m: '%finished_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless completion comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        functions += 1
    assert (functions, count, controls, bindings) == (16, 1120, 48, 16), (functions, count, controls, bindings)
    print(f'Output completion rejects {count} LLVM mutations and {bindings} missing finish bindings; {controls} controls across {functions} readers PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
