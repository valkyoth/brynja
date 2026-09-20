#!/usr/bin/env python3
"""Evaluate retained optimized volatile clearing geometry, not whole-call erasure."""
import argparse
import json
from pathlib import Path
import re

import check_accelerated_staging as shared
import check_kmac_verify_comparisons as comparison
from debug_write_model import Pointer

require = comparison.require
SSA = shared.SSA


def select(core):
    found = [body for name, body in comparison.definitions(core).items()
             if 'secret_memory_volatile23zeroize_region_volatile' in name]
    require(len(found) == 1, 'unique volatile clearing definition')
    return found[0]


def value(token, env):
    if token in env:
        return env[token]
    require(re.fullmatch(r'-?\d+', token) is not None, 'known clearing operand: ' + token)
    return int(token)


def execute(graph, length, base):
    original = Pointer('output', base)
    env = {'%region.0': original, '%region.1': length}
    events, covered = [], set()
    label, predecessor, steps = 'start', None, 0
    while True:
        require(label in graph, 'clearing successor exists')
        covered.add(label)
        lines = graph[label]
        incoming = dict(env)  # LLVM phis read the predecessor's values simultaneously.
        seen_non_phi = False
        for index, line in enumerate(lines):
            steps += 1
            require(steps <= 40 * (length + 1) + 100, 'bounded clearing loop progress')
            dest, op = line.split(' = ', 1) if ' = ' in line else (None, line)
            found = re.fullmatch(r'phi (ptr|i64) (.+)', op)
            if found:
                require(not seen_non_phi, 'phis precede ordinary instructions')
                pairs = re.findall(r'\[ ([^,]+), %([^ ]+) \]', found[2])
                require(', '.join(f'[ {v}, %{p} ]' for v, p in pairs) == found[2]
                        and len({p for _, p in pairs}) == len(pairs), 'complete unique phi edges')
                choices = [v for v, p in pairs if p == predecessor]
                require(len(choices) == 1, 'phi has actual predecessor')
                result = value(choices[0], incoming)
            else:
                seen_non_phi = True
                if found := re.fullmatch(r'getelementptr inbounds nuw i8, ptr (\S+), i64 (\S+)', op):
                    ptr, offset = value(found[1], env), value(found[2], env)
                    require(isinstance(ptr, Pointer) and type(offset) is int and offset >= 0,
                            'nonnegative byte-wise clearing address')
                    result = Pointer(ptr.region, ptr.offset + offset)
                    require(result.region == 'output' and base <= result.offset <= base + length,
                            'clearing pointer within original region or one-past end')
                elif found := re.fullmatch(r'(add|and)( nuw)? i64 (\S+), (\S+)', op):
                    a, b = value(found[3], env), value(found[4], env)
                    require(type(a) is int and type(b) is int, 'integer clearing arithmetic')
                    result = a + b if found[1] == 'add' else a & b
                    require(not found[2] or 0 <= result < 1 << 64, 'non-poison arithmetic')
                    result &= (1 << 64) - 1
                elif found := re.fullmatch(r'icmp( samesign)? (eq|ne|ult|ule|ugt|uge) (i64|ptr) (\S+), (\S+)', op):
                    a, b = value(found[4], env), value(found[5], env)
                    if found[3] == 'ptr':
                        require(isinstance(a, Pointer) and isinstance(b, Pointer)
                                and found[2] in ('eq', 'ne') and not found[1], 'pointer equality only')
                        result = int(a == b) if found[2] == 'eq' else int(a != b)
                    else:
                        require(type(a) is int and type(b) is int and 0 <= a < 1 << 64 and 0 <= b < 1 << 64,
                                'unsigned clearing comparison')
                        require(not found[1] or (a >> 63) == (b >> 63), 'non-poison same-sign comparison')
                        result = int({'eq': a == b, 'ne': a != b, 'ult': a < b,
                                      'ule': a <= b, 'ugt': a > b, 'uge': a >= b}[found[2]])
                elif found := re.fullmatch(r'store volatile i8 (\S+), ptr (\S+), align 1', op):
                    zero, ptr = value(found[1], env), value(found[2], env)
                    require(type(zero) is int and zero == 0 and isinstance(ptr, Pointer)
                            and ptr.region == 'output' and base <= ptr.offset < base + length,
                            'bounded volatile zero-byte store')
                    events.append(('zero', ptr.offset))
                    continue
                elif op == 'fence syncscope("singlethread") seq_cst':
                    events.append(('fence',))
                    continue
                elif found := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', op):
                    condition = value(found[1], env)
                    require(condition in (0, 1) and index == len(lines) - 1, 'terminal clearing branch')
                    predecessor, label = label, found[2] if condition else found[3]
                    break
                elif op == 'ret void':
                    require(index == len(lines) - 1, 'terminal clearing return')
                    require(events == [('zero', base + i) for i in range(length)] + [('fence',)],
                            'every original byte cleared once, in order, before exactly one fence')
                    return covered
                else:
                    raise ValueError('unreviewed optimized clearing instruction: ' + op)
            require(dest is not None, 'clearing computation defines SSA value')
            env[dest] = result
        else:
            raise ValueError('unterminated clearing block')


def lengths():
    return tuple(range(258)) + (511, 512, 513, 1023, 1024, 1025)


def inspect(function):
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    require(symbol is not None and header.startswith('define internal fastcc void '), 'clearing return ABI')
    args = comparison.arguments(header, symbol.end())
    require(len(args) == 2 and comparison.pointer(args[0]) == '%region.0'
            and re.fullmatch(r'i64(?: noundef)?(?: range\(i64 0, -9223372036854775808\))? %region.1', args[1]),
            'borrowed original pointer/length ABI')
    graph = shared.graph(function)
    covered = set()
    for length in lengths():
        covered.update(execute(graph, length, 17))
    require(covered == set(graph), 'all optimized clearing blocks visited')
    return len(lengths())


def cases(record):
    for row, _, core, _ in comparison.cases(record):
        if row['profile'] == 'release':
            yield select(core)


def main(record):
    before = comparison.capture.sources()
    builds = count = 0
    for function in cases(record):
        count += inspect(function)
        builds += 1
    require(builds == 8 and before == comparison.capture.sources(), 'complete unchanged optimized matrix')
    print(f'Volatile clear: {builds} retained optimized bodies, {count} modeled lengths PASS')
    print('Exact in-range volatile zero stores, no payload loads, one compiler fence after complete clearing')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Bounded LLVM analysis, not all-length proof, debug/assembly qualification, whole-call spills or native-platform evidence; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
