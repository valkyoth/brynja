#!/usr/bin/env python3
"""Bounded retained-LLVM checks of output shape/length construction."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_final_input as forwarding

comparison = forwarding.comparison
require = forwarding.require
SSA = forwarding.SSA
LABEL = forwarding.adapter.shape.LABEL
OPERAND = SSA + r'|-?\d+|true|false|null'
POISON = object()
# Only representable Rust slice lengths on the retained 64-bit targets. Large
# values are metadata-model cases, never real slice allocations or Rust calls.
LENGTHS = (0, 1, 2, 63, 64, 65, (1 << 61) - 1, 1 << 61, (1 << 61) + 1, (1 << 63) - 1)
VALIDS = (0, 1, 7, 8, 9, 255) + tuple(i for i in range(256) if i not in (0, 1, 7, 8, 9, 255))


def parse(function):
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    require(symbol is not None and header.startswith('define void @'), 'constructor returns by descriptor')
    args = comparison.arguments(header, symbol.end())
    expected = ('%_0', '%bytes.0', '%bytes.1', '%valid_bits_in_last_byte')
    require(len(args) == 4 and 'sret([32 x i8])' in args[0]
            and all(arg.endswith(' ' + name) for arg, name in zip(args, expected))
            and args[1].startswith('ptr ') and args[2].startswith('i64 ') and args[3].startswith('i8 '), 'constructor argument ABI')
    graph, edges, _ = forwarding.adapter.routes.transfer.finish.graph_info(function)
    patterns = {
        'compare': '(' + SSA + r') = icmp (samesign )?(eq|ult|ugt) i(8|64) (' + OPERAND + '), (' + OPERAND + ')',
        'binary': '(' + SSA + r') = (add|shl) ((?:nuw |nsw )*)i(8|64) (' + OPERAND + '), (' + OPERAND + ')',
        'select': '(' + SSA + r') = select i1 (' + OPERAND + '), i1 (' + OPERAND + '), i1 (' + OPERAND + ')',
        'zext': '(' + SSA + r') = zext i8 (' + OPERAND + ') to i64',
        'overflow': '(' + SSA + r') = tail call \{ i64, i1 } @llvm.uadd.with.overflow.i64\(i64 (' + OPERAND + '), i64 (' + OPERAND + r')\)',
        'extract': '(' + SSA + r') = extractvalue \{ i64, i1 } (' + SSA + '), (0|1)',
        'phi': '(' + SSA + r') = phi i64 \[ (' + OPERAND + '), %(' + LABEL + r') \], \[ (' + OPERAND + '), %(' + LABEL + r') \]',
        'gep': '(' + SSA + r') = getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (\d+)',
        'store': r'store (ptr|i8|i64) (' + OPERAND + '), ptr (' + SSA + r'), align 8',
        'conditional': r'br i1 (' + OPERAND + '), label %(' + LABEL + '), label %(' + LABEL + ')',
        'branch': r'br label %(' + LABEL + ')',
        'return': r'ret void',
    }
    program = {}
    for label, lines in graph.items():
        program[label] = []
        for line in lines:
            matches = [(kind, match.groups()) for kind, pattern in patterns.items()
                       if (match := re.fullmatch(pattern, line))]
            require(len(matches) == 1, 'closed constructor instruction set: ' + line)
            program[label].append(matches[0])
    require(len(program) == 8, 'complete retained constructor block inventory')
    return program


def execute(program, length, valid):
    values = {'%_0': ('result', 0), '%bytes.0': ('payload', 0), '%bytes.1': length,
              '%valid_bits_in_last_byte': valid}
    stores, written, visited = {}, set(), set()
    label, previous = 'start', None

    def get(token):
        if token.startswith('%'):
            require(token in values, 'defined constructor operand')
            return values[token]
        if token in ('true', 'false', 'null'):
            return {'true': True, 'false': False, 'null': None}[token]
        return int(token)

    def unsigned(token, width):
        value = get(token)
        require(type(value) is int and -(1 << (width - 1)) <= value < (1 << width), 'bounded integer operand')
        return value % (1 << width)

    while True:
        require(label in program and label not in visited, 'acyclic defined constructor path')
        visited.add(label)
        successor, returned = None, False
        for kind, args in program[label]:
            require(successor is None and not returned, 'no work after constructor terminator')
            result = None
            if kind == 'compare':
                destination, same, predicate, width, left, right = args
                width = int(width)
                left, right = unsigned(left, width), unsigned(right, width)
                require(not same or (left >> (width - 1)) == (right >> (width - 1)), 'samesign operands satisfy LLVM premise')
                result = {'eq': left == right, 'ult': left < right, 'ugt': left > right}[predicate]
            elif kind == 'binary':
                destination, operator, flags, width, left, right = args
                width = int(width)
                left, right = unsigned(left, width), unsigned(right, width)
                require(operator != 'shl' or right < width, 'bounded shift')
                mathematical = left + right if operator == 'add' else left << right
                signed = lambda value: value if value < (1 << (width - 1)) else value - (1 << width)
                signed_result = signed(left) + signed(right) if operator == 'add' else signed(left) << right
                poison = ('nuw' in flags and mathematical >= (1 << width) or
                          'nsw' in flags and not -(1 << (width - 1)) <= signed_result < (1 << (width - 1)))
                # LLVM 20 speculatively computes the nuw sum even on the error
                # edge. Its poison is harmless only while unobserved; selected
                # phi/store operands still pass through unsigned() below.
                result = POISON if poison else mathematical % (1 << width)
            elif kind == 'select':
                destination, condition, yes, no = args
                condition, yes, no = get(condition), get(yes), get(no)
                require(all(type(value) is bool for value in (condition, yes, no)), 'boolean selection')
                result = yes if condition else no
            elif kind == 'zext':
                destination, operand = args
                result = unsigned(operand, 8)
            elif kind == 'overflow':
                destination, left, right = args
                total = unsigned(left, 64) + unsigned(right, 64)
                result = total % (1 << 64), total >= (1 << 64)
            elif kind == 'extract':
                destination, aggregate, index = args
                aggregate = get(aggregate)
                require(isinstance(aggregate, tuple) and len(aggregate) == 2
                        and type(aggregate[0]) is int and type(aggregate[1]) is bool, 'overflow intrinsic result')
                result = aggregate[int(index)]
            elif kind == 'phi':
                destination, left, first, right, second = args
                require(first != second and previous in (first, second), 'actual phi predecessor')
                result = unsigned(left if previous == first else right, 64)
            elif kind == 'gep':
                destination, base, offset = args
                base = get(base)
                require(isinstance(base, tuple) and base[0] == 'result' and 0 <= base[1] + int(offset) < 32,
                        'only bounded result field addressing; never payload')
                result = base[0], base[1] + int(offset)
            elif kind == 'store':
                field, operand, address = args
                address = get(address)
                width = 1 if field == 'i8' else 8
                require(isinstance(address, tuple) and address[0] == 'result' and 0 <= address[1] <= 32 - width,
                        'constructor writes only bounded result descriptor')
                offsets = set(range(address[1], address[1] + width))
                require(not offsets & written, 'result fields do not overlap or repeat')
                value = get(operand) if field == 'ptr' else unsigned(operand, width * 8)
                require(field != 'ptr' or value is None or value == ('payload', 0), 'original output pointer or error null')
                written.update(offsets)
                stores[address[1]] = field, value
            elif kind == 'conditional':
                condition, yes, no = args
                condition = get(condition)
                require(type(condition) is bool, 'boolean constructor branch')
                successor = yes if condition else no
            elif kind == 'branch':
                successor = args[0]
            elif kind == 'return':
                returned = True
            if kind not in ('store', 'conditional', 'branch', 'return'):
                require(destination not in values, 'single-assignment constructor value')
                values[destination] = result
        if returned:
            return stores, visited
        require(successor is not None, 'terminated constructor block')
        previous, label = label, successor


def inspect(function):
    program = parse(function)
    covered = set()
    for length in LENGTHS:
        for valid in VALIDS:
            stores, visited = execute(program, length, valid)
            covered.update(visited)
            bits = 0 if length == 0 else (length - 1) * 8 + valid
            shape = valid == 0 if length == 0 else 1 <= valid <= 8
            error = 0 if not shape else 2 if bits >= (1 << 64) else None
            expected = ({0: ('ptr', None), 8: ('i8', error)} if error is not None else
                        {0: ('ptr', ('payload', 0)), 8: ('i64', length), 16: ('i64', bits), 24: ('i8', valid)})
            require(stores == expected, f'constructor result matches mathematical shape/length contract: {length}, {valid}')
    require(covered == set(program), 'every retained constructor block exercised')
    return len(LENGTHS) * len(VALIDS)


def cases(record):
    seen = set()
    for row, function, callees in forwarding.adapter.cases(record):
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'unique validated constructor artifact')
        text = paths[0].read_text()
        name = forwarding.constructor(text)
        forwarding.inspect(function, callees, name)
        if paths[0] not in seen:
            seen.add(paths[0])
            yield comparison.definitions(text)[name]


def main(record):
    before = comparison.capture.sources()
    counts = [inspect(function) for function in cases(record)]
    require(len(counts) == 8 and sum(counts) == 20480 and before == comparison.capture.sources(), 'unchanged complete constructor matrix')
    print('FIPS 202 output constructor: 8 optimized bodies, 20,480 metadata cases, all 64 blocks PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Bounded LLVM metadata model; not all lengths, reader semantics, padding initialization, machine-code or register/spill erasure proof')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
