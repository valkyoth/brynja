#!/usr/bin/env python3
"""Mutate retained descriptor forwarding without executing cryptography."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_final_input as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace):
    result, decision, error, reader, index = trace.input_details
    start = trace.graph['start']
    invocation = start[-2]
    name, args = check.adapter.routes.guard.call(invocation)
    for old, new in ((name, 'unreviewed_constructor'), ('%output.0', '%self.0'),
                     ('%output.1', '0'), ('%valid', '0'), ('sret([32 x i8])', 'sret([24 x i8])'),
                     (args[0], args[0].replace(result, '%_0'))):
        yield 'constructor binding/forwarding', function.replace(invocation, invocation.replace(old, new), 1)
    for injection in ('store i64 0, ptr %output.0, align 1', 'call void @unreviewed(ptr %output.0)'):
        yield 'pre-constructor side effect', replace_block(function, 'start', start[:-2] + [injection] + start[-2:])
    deciding = trace.graph[decision]
    yield 'wrong constructor result', function.replace(deciding[0], deciding[0].replace('ptr ' + result, 'ptr %_0'), 1)
    yield 'inverted constructor discriminator', function.replace(deciding[1], deciding[1].replace('icmp eq', 'icmp ne'), 1)
    condition, yes, no = check.adapter.shape.branch(trace, decision)
    for branch in (f'br i1 {condition}, label %{no}, label %{yes}', f'br label %{reader}', f'br label %{error}'):
        yield 'bypassed constructor decision', replace_block(function, decision, deciding[:-1] + [branch])
    yield 'rejected constructor reaches reader', replace_block(function, error, ['br label %' + reader])
    yield 'decision clobbers constructor result', replace_block(function, decision,
        ['store ptr null, ptr ' + result + ', align 8'] + deciding)
    lines = trace.graph[reader]
    for line in lines[:index]:
        if 'getelementptr ' in line:
            for old, new in (('i64 8', 'i64 7'), ('i64 9', 'i64 10')):
                if old in line:
                    yield 'shift descriptor field', function.replace(line, line.replace(old, new), 1)
        elif ' = load i8,' in line:
            yield 'wrong descriptor load', function.replace(line, line.replace('load i8', 'load ptr'), 1)
        elif line.startswith('store '):
            yield 'missing field store', replace_block(function, reader, [entry for entry in lines if entry != line])
            yield 'duplicate field store', replace_block(function, reader, [line] + lines)
        elif 'call void @llvm.memcpy.' in line:
            for width in (0, 8, 22, 24):
                yield 'wrong tail-copy width', function.replace(line, line.replace('i64 23', 'i64 ' + str(width)), 1)
            _, params = check.adapter.routes.guard.call(line)
            for parameter in (0, 1):
                pointer = check.comparison.pointer(params[parameter])
                yield 'wrong copy endpoint', function.replace(line,
                    line.replace(params[parameter], params[parameter].replace(pointer, '%_0')), 1)
            yield 'missing descriptor copy', replace_block(function, reader, [entry for entry in lines if entry != line])
            yield 'duplicate descriptor copy', replace_block(function, reader, lines[:index] + [line] + lines[index:])
        elif 'call void @llvm.lifetime.end.' in line:
            yield 'missing constructor lifetime end', replace_block(function, reader, [entry for entry in lines if entry != line])
            yield 'premature constructor lifetime end', replace_block(function, reader, [line] + lines)
    call = lines[index]
    _, args = check.adapter.routes.guard.call(call)
    pointer = check.comparison.pointer(args[3])
    yield 'reader receives wrong descriptor', function.replace(call, call.replace(args[3], args[3].replace(pointer, result)), 1)
    yield 'pre-reader unknown call', replace_block(function, reader, lines[:index] + ['call void @unreviewed(ptr ' + pointer + ')'] + lines[index:])


def constructor_mutations():
    body = ('define void @_ZN16brynja_hash_sha310bit_string13Fips202Output3new'
            '(ptr sret([32 x i8]) %out, ptr %bytes, i64 %length, i8 %valid) {\nstart:\n  ret void\n}')
    return rejects(check.constructor, body, [
        ('missing definition', ''), ('wrong symbol', body.replace('13Fips202Output3new', 'Other')),
        ('result width', body.replace('[32 x i8]', '[24 x i8]')),
        ('return ABI', body.replace('define void', 'define i64')),
        ('length ABI', body.replace('i64 %length', 'i32 %length')),
        ('valid ABI', body.replace('i8 %valid', 'i64 %valid')),
    ])


def main(record):
    count = controls = functions = 0
    for function, callees, new in check.cases(record):
        inspect = lambda value: check.inspect(value, callees, new)
        trace = inspect(function)
        count += rejects(inspect, function, mutations(function, trace))
        local_names = {match[1] for lines in trace.graph.values() for line in lines
                       if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%forward_' + m[0][1:] if m[0] in local_names else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless input-forwarding comment\n', 1)):
            assert changed != function
            assert inspect(changed).input_copies == trace.input_copies
            controls += 1
        functions += 1
    bindings = constructor_mutations()
    assert (functions, count, controls, bindings) == (16, 640, 48, 6)
    print(f'KMAC final input rejects {count} LLVM mutations and {bindings} constructor-binding regressions; {controls} naming/comment controls across {functions} adapters PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
