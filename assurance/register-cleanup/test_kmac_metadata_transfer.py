#!/usr/bin/env python3
"""Retained KMAC descriptor-transfer mutations; no compiler/runtime execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_metadata_transfer as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def decisions(function, graph, edges, label, success, size):
    kind, value, _ = check.discriminator(graph, edges, label, success, size)
    lines = graph[label]
    branch = re.fullmatch(r'br i1 (' + check.SSA + r'), label %(' + check.guard.LABEL + r'), label %(' + check.guard.LABEL + ')', lines[-1])
    compare = next(line for line in lines if line.startswith(branch[1] + ' = '))
    yield 'inverted error comparison', function.replace(compare, compare.replace('icmp eq ', 'icmp ne '), 1)
    wrong = '3' if size == 24 else '%foreign'
    yield 'wrong error discriminator', function.replace(compare, re.sub(r', (2|null)$', ', ' + wrong, compare), 1)
    yield 'test unrelated result value', function.replace(compare, compare.replace(value + ',', '%foreign,'), 1)
    yield 'exchange success/error edges', replace_block(function, label,
        lines[:-1] + [f'br i1 {branch[1]}, label %{branch[3]}, label %{branch[2]}'])
    for end in ('br label %' + success, 'ret void', 'unreachable'):
        yield 'bypass result decision', replace_block(function, label, lines[:-1] + [end])


def callee_mutants(function, state_callees):
    size, label, decision, owner, _ = check.transfer(function, state_callees)
    graph, edges, origin = check.finish.graph_info(function)
    yield from decisions(function, graph, edges, decision, label, size)
    for current, lines in graph.items():
        if current != label and current not in edges[label][0]:
            continue
        for index, line in enumerate(lines):
            if line.startswith('store '):
                yield 'missing result field', replace_block(function, current, lines[:index] + lines[index + 1:])
                yield 'duplicate result field', replace_block(function, current, lines[:index] + [line] + lines[index:])
                match = re.fullmatch(r'store (ptr|i\d+) (.+), ptr (' + check.SSA + r'), align (\d+)', line)
                wrong_value = '%foreign' if match[1] == 'ptr' else '0'
                # Only discriminator/metadata values are in scope, not the
                # content of the remaining reader descriptor fields.
                offset = origin(match[3])[1]
                if offset in (size - 8, 8 if size == 24 else 0):
                    yield 'wrong metadata or discriminator value', function.replace(line,
                        line.replace(match[1] + ' ' + match[2] + ',', match[1] + ' ' + wrong_value + ','), 1)
                yield 'wrong output owner', function.replace(line,
                    line.replace(', ptr ' + match[3] + ',', ', ptr %foreign,'), 1)
                yield 'wrong output width', function.replace(line,
                    line.replace('store ' + match[1] + ' ', 'store i128 ', 1), 1)
            if line == owner + ' = load ptr, ptr %self, align 8':
                yield 'load metadata from wrong Core', function.replace(line, line.replace('%self', '%input'), 1)
                yield 'metadata load after transfer', replace_block(function, current,
                    lines[:index] + lines[index + 1:-1] + [line, lines[-1]])
            if line.startswith('call void @') and 'llvm.' not in line:
                name, args = check.guard.call(line)
                yield 'unbound state cleanup', function.replace(line, line.replace('@' + name + '(', '@unreviewed('), 1)
                yield 'wrong state cleanup pointer', function.replace(line,
                    line.replace(check.comparison.pointer(args[0]), '%foreign'), 1)
                yield 'missing state cleanup', replace_block(function, current, lines[:index] + lines[index + 1:])
            if line.startswith('ret void'):
                yield 'write after ownership transfer', replace_block(function, current,
                    ['store ptr %foreign, ptr %_0, align 8'] + lines)
                yield 'unreviewed post-transfer call', replace_block(function, current,
                    ['call void @unreviewed(ptr %_0)'] + lines)
        if current == label:
            for end in ('ret void', 'br label %' + label, 'unreachable'):
                yield 'missing success-return diamond', replace_block(function, current, lines[:-1] + [end])
    output_stores = check.stores(graph, origin)
    for pointer in {re.fullmatch(r'store (?:ptr|i\d+) .+, ptr (' + check.SSA + r'), align \d+', graph[lab][index])[1]
                    for lab, index, _, _, _, _ in output_stores if lab == label}:
        if pointer == '%_0':
            continue
        gep = next(line for lines in graph.values() for line in lines if line.startswith(pointer + ' = '))
        for offset in (0, size - 1, size):
            yield 'misplaced or overlapping output field', function.replace(gep, re.sub(r'i64 \d+$', f'i64 {offset}', gep), 1)
    yield 'overwrite original Core metadata pointer', replace_block(function, 'start',
        ['store ptr %input, ptr %self, align 8'] + graph['start'])


def caller_mutants(verifier, function, names, defined, state_callees):
    size = check.transfer(function, state_callees)[0]
    graph, edges, _, origin, gate = check.early.prelude(verifier, names, defined)
    _, _, _, _, _, owner, extraction = check.early.optimized.inventory(verifier, names, defined)
    yield from decisions(verifier, graph, edges, gate, extraction, size)
    kind, value, _ = check.discriminator(graph, edges, gate, extraction, size)
    load = next(line for line in graph[gate] if line.startswith(value + ' = '))
    source = re.search(r', ptr (' + check.SSA + ')', load)[1]
    yield 'caller tests wrong result descriptor', verifier.replace(load, load.replace(', ptr ' + source + ',', ', ptr %candidate,'), 1)
    output_load = next(line for line in graph[extraction] if line.startswith(owner + ' = '))
    pointer = re.search(r', ptr (' + check.SSA + ')', output_load)[1]
    field = next(line for lines in graph.values() for line in lines if line.startswith(pointer + ' = '))
    for offset in (0, 8, size - 1, size):
        yield 'caller extracts wrong metadata field', verifier.replace(field, re.sub(r'i64 \d+$', f'i64 {offset}', field), 1)
    call = next(line for line in graph[gate] if '6finish' in line)
    name, args = check.guard.call(call)
    slot = check.comparison.pointer(args[0])
    for current, position in ((gate, graph[gate].index(call) + 1), (extraction, 0)):
        for injected in (f'store ptr %foreign, ptr {slot}, align 8', f'call void @unreviewed(ptr {slot})',
                         f'call void @llvm.lifetime.end.p0(ptr nonnull {slot})'):
            yield 'result clobber before metadata extraction', replace_block(verifier, current,
                graph[current][:position] + [injected] + graph[current][position:])
    for line in graph[extraction]:
        if '@llvm.memcpy.p0.p0.i64(' in line:
            _, copy_args = check.guard.call(line)
            for replacement in (copy_args[0].replace(check.comparison.pointer(copy_args[0]), slot),
                                copy_args[0].replace(check.comparison.pointer(copy_args[0]), '%candidate')):
                yield 'reader copy clobbers borrowed/result owner', verifier.replace(line, line.replace(copy_args[0], replacement), 1)
            yield 'reader copy exceeds bounded descriptor', verifier.replace(line, line.replace('i64 15', 'i64 32'), 1)
            break
    yield 'different finish callee', verifier.replace(call, call.replace('@' + name + '(', '@unreviewed_finish('), 1)
    yield 'finish returns into wrong slot', verifier.replace(call,
        call.replace(args[0], args[0].replace(check.comparison.pointer(args[0]), '%candidate')), 1)


def main(record):
    callee_count = caller_count = pairs = controls = 0
    for _, verifier, function, names, defined, state_callees in check.cases(record):
        inspect_callee = lambda value: check.inspect(verifier, value, names, defined, state_callees)
        inspect_caller = lambda value: check.inspect(value, function, names, defined, state_callees)
        callee_count += rejects(inspect_callee, function, callee_mutants(function, state_callees))
        caller_count += rejects(inspect_caller, verifier, caller_mutants(verifier, function, names, defined, state_callees))
        # Keep the call binding while renaming only internal descriptor SSA.
        owner = check.transfer(function, state_callees)[3]
        for original, inspect, metadata in ((function, inspect_callee, owner),
                                           (verifier, inspect_caller, check.early.optimized.inventory(verifier, names, defined)[5])):
            baseline = inspect(original)
            for changed in (
                    re.sub(re.escape(metadata) + r'(?![-.$\w])', '%transferred_metadata', original),
                    re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), original),
                    original.replace('start:\n', 'start:\n; harmless transfer qualification comment\n', 1)):
                assert changed != original and inspect(changed) == baseline
                controls += 1
        pairs += 1
    assert (pairs, callee_count, caller_count, controls) == (24, 996, 504, 144)
    print(f'KMAC metadata transfer rejects {callee_count} callee and {caller_count} caller mutations; {controls} owner/label/comment controls across {pairs} pairs PASS')
    print('Retained LLVM-text mutations only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
