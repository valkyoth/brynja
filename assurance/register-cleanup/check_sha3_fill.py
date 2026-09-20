#!/usr/bin/env python3
"""Model retained optimized portable fill geometry, not permutation/erasure proof."""
import argparse
import json
from pathlib import Path
import re

import check_accelerated_staging as shared

comparison = shared.comparison
require = comparison.require
SSA = shared.SSA
ATOM = r'(?:' + SSA + r'|-?\d+)'


def compile_function(function, sha3, core):
    definitions = comparison.definitions(sha3)
    core_defs = comparison.definitions(core)
    names = {
        shared.unique(definitions, '11permutation6native6scalar'): 'permute',
        shared.unique(core_defs, '18copy_secret_region'): 'copy',
        shared.unique(core_defs, '18clear_owned_region'): 'clear',
        'llvm.umin.i64': 'min',
    }
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    params = comparison.arguments(header, symbol.end())
    require(len(params) == 2 and comparison.pointer(params[0]) == '%self'
            and params[1] == 'i64 noundef %count', 'borrowed fill ABI')
    result = {}
    for label, lines in shared.graph(function).items():
        result[label] = code = []
        for line in lines:
            found = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr (' + SSA + '), i64 (' + ATOM + ')', line)
            if found:
                code.append(('gep', *found.groups()))
                continue
            found = re.fullmatch('(' + SSA + r') = load i8, ptr (' + SSA + '), align 1', line)
            if found:
                code.append(('load', *found.groups()))
                continue
            found = re.fullmatch('(' + SSA + r') = phi i(8|64) (.+)', line)
            if found:
                pairs = re.findall(r'\[ (' + ATOM + '), %(' + shared.LABEL + r') \]', found[3])
                require(len(pairs) > 0 and len({pred for _, pred in pairs}) == len(pairs)
                        and ', '.join(f'[ {value}, %{pred} ]' for value, pred in pairs) == found[3], 'closed fill phi')
                code.append(('phi', found[1], int(found[2]), dict((p, v) for v, p in pairs)))
                continue
            found = re.fullmatch('(' + SSA + r') = (add|sub)((?: nuw| nsw)*) i(8|64) (' + ATOM + '), (' + ATOM + ')', line)
            if found:
                code.append(('arithmetic', *found.groups()))
                continue
            found = re.fullmatch('(' + SSA + r') = (zext|trunc)(?: nuw)? i(8|64) (' + ATOM + ') to i(8|64)', line)
            if found:
                code.append(('convert', *found.groups()))
                continue
            found = re.fullmatch('(' + SSA + r') = icmp (?:samesign )?(eq|ugt|ult) i(8|64) (' + ATOM + '), (' + ATOM + ')', line)
            if found:
                code.append(('compare', *found.groups()))
                continue
            found = re.fullmatch('store i8 (' + ATOM + '), ptr (' + SSA + '), align 1', line)
            if found:
                code.append(('store', *found.groups()))
                continue
            if 'tail call ' in line:
                symbol = re.search(comparison.SYMBOL, line)
                require(symbol is not None and symbol[1] in names, 'reviewed fill callee')
                callee = names[symbol[1]]
                prefix = line[:symbol.start()]
                if callee == 'permute':
                    require(prefix == 'tail call fastcc void ', 'permutation borrowed ABI')
                    output = None
                else:
                    found = re.fullmatch('(' + SSA + ') = tail call noundef i' + ('64' if callee == 'min' else '8') + ' ', prefix)
                    require(found is not None, 'value-free fill call result ABI')
                    output = found[1]
                args = comparison.arguments(line, symbol.end())
                require(re.fullmatch(r'(?: #\d+)?', line[line.rfind(')') + 1:]), 'plain fill call suffix')
                expected = {'permute': ('ptr',) * 4, 'copy': ('ptr', 'i64', 'ptr', 'i64'),
                            'clear': ('ptr', 'i64'), 'min': ('i64', 'i64')}[callee]
                require(len(args) == len(expected), 'fill call arity')
                operands = []
                for arg, kind in zip(args, expected):
                    if kind == 'ptr':
                        operands.append(comparison.pointer(arg))
                    else:
                        found = re.fullmatch('i64 (?:noundef )?(' + ATOM + ')', arg)
                        require(found is not None, 'integer fill argument')
                        operands.append(found[1])
                code.append(('call', callee, output, operands))
                continue
            found = re.fullmatch('br i1 (' + SSA + '), label %(' + shared.LABEL + '), label %(' + shared.LABEL + ')', line)
            if found:
                code.append(('branch', *found.groups()))
                continue
            found = re.fullmatch('br label %(' + shared.LABEL + ')', line)
            if found:
                code.append(('jump', found[1]))
                continue
            found = re.fullmatch('ret i8 (' + ATOM + ')', line)
            require(found is not None, 'unreviewed fill instruction: ' + line)
            code.append(('return', found[1]))
        require(code and code[-1][0] in ('branch', 'jump', 'return')
                and not any(item[0] in ('branch', 'jump', 'return') for item in code[:-1]), 'one terminal instruction per block')
    require(len(result) == 10 and 'start' in result, 'ten-block fill inventory')
    rates = {int(item[5]) for block in result.values() for item in block
             if item[0] == 'arithmetic' and item[2] == 'sub' and item[5] in ('136', '168')}
    require(len(rates) == 1, 'one reviewed rate identity')
    return result, rates.pop()


def execute(program, count, cursor, old, failed_copy):
    values = {'%self': ('owner', 0), '%count': count}
    events, previous, label = [], None, 'start'
    copies = 0
    def get(token):
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        require(token in values, 'defined fill operand')
        return values[token]
    for _ in range(64):
        require(label in program, 'known fill successor')
        updates = {}
        # Phi values are simultaneous, including loop-carried values.
        for item in program[label]:
            if item[0] == 'phi':
                _, output, width, inputs = item
                require(previous in inputs, 'fill phi predecessor')
                updates[output] = get(inputs[previous]) % (1 << width)
        values.update(updates)
        for item in program[label]:
            kind = item[0]
            if kind == 'phi':
                continue
            if kind == 'gep':
                _, output, base, offset = item
                pointer, displacement = get(base), get(offset)
                require(isinstance(pointer, tuple) and isinstance(displacement, int), 'typed fill address')
                address = pointer[1] + displacement
                require(pointer[0] == 'owner' and 0 <= address <= 1040, 'owner-relative fill address')
                values[output] = ('owner', address)
            elif kind == 'load':
                require(get(item[2]) == ('owner', 1039), 'only cursor metadata loaded, never payload')
                values[item[1]] = cursor
            elif kind == 'store':
                require(get(item[2]) == ('owner', 1039), 'only cursor metadata stored directly')
                cursor = get(item[1]) % 256
                events.append(('cursor', cursor))
            elif kind == 'arithmetic':
                _, output, operation, flags, width, left, right = item
                width = int(width)
                left, right = get(left), get(right)
                number = left + right if operation == 'add' else left - right
                require('nuw' not in flags or 0 <= number < 1 << width, 'no unsigned poison')
                require('nsw' not in flags or -(1 << (width - 1)) <= number < 1 << (width - 1), 'no signed poison')
                values[output] = number % (1 << width)
            elif kind == 'convert':
                _, output, _, _, operand, width = item
                values[output] = get(operand) % (1 << int(width))
            elif kind == 'compare':
                _, output, op, width, left, right = item
                left, right = get(left) % (1 << int(width)), get(right) % (1 << int(width))
                values[output] = {'eq': left == right, 'ugt': left > right, 'ult': left < right}[op]
            elif kind == 'call':
                _, callee, output, operands = item
                args = [get(operand) for operand in operands]
                if callee == 'min':
                    values[output] = min(args)
                elif callee == 'permute':
                    require(args == [('owner', n) for n in (48, 752, 792, 832)], 'exact state and scratch permutation borrows')
                    events.append(('permute',))
                elif callee == 'clear':
                    require((args[0], args[1]) in {(('owner', 752), 40), (('owner', 792), 40), (('owner', 832), 200)}, 'whole permutation scratch clear')
                    events.append(('clear', args[0][1], args[1]))
                    values[output] = 4 if old else 255
                else:
                    require(args[1] == args[3] and 0 < args[1] <= 168, 'equal bounded copy slices')
                    require(isinstance(args[0], tuple) and isinstance(args[2], tuple)
                            and args[0][0] == args[2][0] == 'owner', 'owner-bound copy')
                    events.append(('copy', args[0][1], args[2][1], args[1]))
                    copies += 1
                    values[output] = 0 if copies == failed_copy else (4 if old else 255)
            elif kind == 'return':
                return get(item[1]) % 256, cursor, events
            elif kind in ('branch', 'jump'):
                previous, label = label, (item[2] if get(item[1]) else item[3]) if kind == 'branch' else item[1]
        # A successor is selected by the compiled terminal instruction.
    raise ValueError('fill loop failed to terminate within bounded campaign')


def expected(rate, count, cursor, old, failed_copy):
    success = 5 if old else 255
    events = []
    if count > 168:
        return 3, cursor, events
    if count == 0:
        return success, cursor, events
    if cursor > rate:
        return 0, cursor, events
    offset, copies = 0, 0
    while offset < count:
        if cursor == rate:
            events += [('permute',), ('clear', 752, 40), ('clear', 792, 40), ('clear', 832, 200), ('cursor', 0)]
            cursor = 0
        width = min(count - offset, rate - cursor)
        events.append(('copy', 584 + offset, 48 + cursor, width))
        copies += 1
        if copies == failed_copy:
            return 4, cursor, events
        cursor += width
        offset += width
        events.append(('cursor', cursor))
    return success, cursor, events


def scenarios(rate):
    pairs = {(count, cursor) for count in range(170) for cursor in (0, 1, rate - 1, rate, rate + 1, 255)}
    pairs |= {(count, cursor) for count in (0, 1, rate - 1, rate, 168, 169, (1 << 64) - 1) for cursor in range(256)}
    for count, cursor in sorted(pairs):
        yield count, cursor, 0
    for count in (1, rate, 168):
        for cursor in (0, rate - 1, rate):
            for failure in (1, 2):
                yield count, cursor, failure


def inspect(function, sha3, core, compiler, thorough=True):
    require(compiler in ('1.90.0', '1.98.1'), 'reviewed fill compiler')
    program, rate = compile_function(function, sha3, core)
    inputs = scenarios(rate) if thorough else ((n, p, failure) for n in (0, 1, 168, 169) for p in (0, rate - 1, rate, 255) for failure in (0, 1, 2))
    count = 0
    for length, cursor, failure in inputs:
        actual = execute(program, length, cursor, compiler == '1.90.0', failure)
        require(actual == expected(rate, length, cursor, compiler == '1.90.0', failure),
                f'fill geometry/result mismatch: rate={rate}, count={length}, cursor={cursor}, failed_copy={failure}')
        count += 1
    return rate, count


def cases(record):
    document = json.loads(record.read_text())
    comparison.validate_record(document, record.parent)
    for row in document['records']:
        if row['profile'] != 'release':
            continue
        def artifact(package):
            return next((record.parent / path).read_text() for path in row['artifacts']
                        if Path(path).name.startswith(package + '-') and path.endswith('.ll'))
        sha3, core = artifact('brynja_hash_sha3'), artifact('brynja_core')
        functions = [f for name, f in comparison.definitions(sha3).items() if '6sponge' in name and '12fill_staging' in name]
        require(len(functions) == 2, 'both fill rate instantiations')
        for function in functions:
            yield function, sha3, core, row['compiler'].splitlines()[0].split()[1]


def main(record):
    before = comparison.capture.sources()
    results = [inspect(*case) for case in cases(record)]
    require(len(results) == 16 and [rate for rate, _ in results].count(136) == 8
            and before == comparison.capture.sources(), 'complete unchanged fill matrix')
    print(f'Portable fill geometry: 16 optimized bodies PASS; {sum(count for _, count in results)} modeled cases')
    print('Only cursor metadata loaded/stored directly; state-to-staging copy geometry and scratch-clear request ordering match model')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not permutation/copy/clear implementation, all-input formal proof, debug, spills or native-platform qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
