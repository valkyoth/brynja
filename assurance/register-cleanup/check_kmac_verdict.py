#!/usr/bin/env python3
"""Check retained KMAC verdict forwarding; not whole-verifier qualification."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_verify_comparisons as comparison

require = comparison.require
SSA = r'%[-.$\w]+'
LEAF = 'secret_memory_predicate12mask_is_zero'
APPLY = 'secret_memory_predicate5apply'


def role(name):
    if comparison.PREDICATE in name:
        return 'root'
    if APPLY in name:
        return 'apply'
    if 'brynja_core' in name and '6choice' in name and '6Choice8from_lsb' in name:
        return 'choice'
    if LEAF in name:
        return 'leaf'
    raise ValueError('unreviewed verdict callee: ' + name)


def scalar(argument, values):
    match = re.fullmatch(r'i8 (?:(?:noundef|zeroext) )*(' + SSA + r'|-1)', argument)
    require(match is not None, 'expected byte mask/verdict argument')
    value = ('mask', -1) if match[1] == '-1' else values.get(match[1])
    require(value is not None, 'defined scalar argument')
    return value


def inspect(text):
    functions = comparison.definitions(text)
    roots = [name for name in functions if comparison.PREDICATE in name]
    require(len(roots) == 1, 'unique verdict entry')
    visited = []

    def walk(name, inputs):
        require(name in functions and name not in visited, 'complete acyclic verdict chain')
        visited.append(name)
        function = functions[name]
        header = function.splitlines()[0]
        symbol = re.search(comparison.SYMBOL, header)
        params = comparison.arguments(header, symbol.end())
        kind = role(name)
        expected = {'root': ('i8', ['%difference']),
                    'apply': ('i1', ['%byte', '%mask']),
                    'choice': ('i8', ['%value'])}[kind]
        require(re.search(r'\b' + expected[0] + r'\s*$', header[:symbol.start()]), 'verdict return ABI')
        matches = [re.search(r'(' + SSA + r')$', param) for param in params]
        require(all(matches), 'named verdict parameters')
        names = [match[1] for match in matches]
        require(names == expected[1] and len(inputs) == len(params), 'verdict argument inventory')
        for param, value in zip(params, inputs):
            if value[0] == 'ptr':
                comparison.pointer(param)
            else:
                require(param.startswith('i8 '), 'public scalar ABI')
        values = dict(zip(names, inputs))
        slots, returned, calls = {}, None, []
        for raw in function.splitlines()[1:-1]:
            line = raw.strip()
            if not line or line.startswith(';') or line == 'start:' or line.startswith('#dbg_declare('):
                continue
            line = re.sub(r', !dbg !\d+$', '', line)
            require(returned is None, 'instruction after verdict return')
            allocation = re.fullmatch('(' + SSA + r') = alloca \[(1|8) x i8\], align (1|8)', line)
            if allocation:
                require(allocation[1] not in values and allocation[1] not in slots
                        and allocation[2] == allocation[3], 'unique debug slot')
                slots[allocation[1]] = int(allocation[2])
                continue
            store = re.fullmatch(r'store (ptr|i8) (' + SSA + r'), ptr (' + SSA + r'), align (1|8)', line)
            if store:
                width = 8 if store[1] == 'ptr' else 1
                value = values.get(store[2])
                require(slots.get(store[3]) == width and int(store[4]) == width, 'store only to local debug slot')
                require(value is not None and value[0] in (('ptr',) if width == 8 else ('mask', 'verdict8')),
                        'debug store contains only pointer, public mask or normalized verdict')
                continue
            call = re.fullmatch('(' + SSA + r') = (?:tail )?call (?:fastcc )?(?:(?:noundef|zeroext) )*'
                                r'(i1|i8|i32) ' + comparison.SYMBOL + r'(.*)', line)
            if call:
                target = call[3]
                arguments = comparison.arguments(line, line.index('@' + target + '(') + len(target) + 2)
                # No operand bundles or other suffix operations in this closed grammar.
                end = line.rfind(')')
                require(re.fullmatch(r'(?: #\d+)?', line[end + 1:]), 'plain verdict call suffix')
                target_role = role(target)
                if target_role in ('leaf', 'apply'):
                    require(len(arguments) == 2, 'predicate argument count')
                    pointer = values.get(comparison.pointer(arguments[0]))
                    require(pointer == ('ptr', 'difference') and scalar(arguments[1], values) == ('mask', -1),
                            'predicate receives original difference pointer and full-byte mask')
                    if target_role == 'leaf':
                        require(target in functions and call[2] == 'i32', 'retained private predicate ABI')
                        value = ('raw', 'difference')
                    else:
                        require(kind == 'root' and call[2] == 'i1', 'apply forwarding ABI')
                        value = walk(target, [pointer, ('mask', -1)])
                else:
                    require(target_role == 'choice' and kind == 'root' and len(arguments) == 1
                            and call[2] == 'i8', 'Choice construction ABI')
                    operand = scalar(arguments[0], values)
                    require(operand == ('verdict8', 'difference'), 'Choice contains normalized predicate only')
                    value = walk(target, [operand])
                require(call[1] not in values and call[1] not in slots, 'unique verdict SSA definition')
                values[call[1]] = value
                calls.append(target_role)
                continue
            transform = re.fullmatch('(' + SSA + r') = (icmp eq i32|zext i1|and i8) (' + SSA + r')(, 1| to i8)', line)
            if transform:
                name_out, operation, operand, suffix = transform.groups()
                require(name_out not in values and name_out not in slots, 'unique verdict transform')
                if operation == 'icmp eq i32':
                    require(suffix == ', 1' and values.get(operand) == ('raw', 'difference'), 'normalize private predicate against one')
                    value = ('verdict1', 'difference')
                elif operation == 'zext i1':
                    require(suffix == ' to i8' and values.get(operand) == ('verdict1', 'difference'), 'widen normalized Boolean only')
                    value = ('verdict8', 'difference')
                else:
                    require(kind == 'choice' and suffix == ', 1' and values.get(operand) == ('verdict8', 'difference'), 'Choice low-bit mask')
                    value = ('verdict8', 'difference')
                values[name_out] = value
                continue
            result = re.fullmatch(r'ret (i1|i8) (' + SSA + ')', line)
            if result:
                expected_value = ('verdict1' if kind == 'apply' else 'verdict8', 'difference')
                require(result[1] == expected[0] and values.get(result[2]) == expected_value, 'return derived normalized verdict')
                returned = expected_value
                continue
            raise ValueError('unreviewed verdict instruction: ' + line)
        require(returned is not None, 'missing verdict return')
        require(calls in ([['leaf'], ['apply', 'choice']] if kind == 'root'
                         else [['leaf']] if kind == 'apply' else [[]]), 'exact verdict call inventory')
        return returned

    walk(roots[0], [('ptr', 'difference')])
    return [(name, functions[name]) for name in visited]


def main(record):
    before = comparison.capture.sources()
    count = 0
    for row, _, core, assembly in comparison.cases(record):
        chain = inspect(core)
        require(len(chain) == (3 if row['profile'] == 'debug' else 1), 'complete verdict chain for profile')
        comparison.predicate.inspect(assembly, row['target'].startswith('aarch64'))
        count += len(chain)
    require(count == 32 and before == comparison.capture.sources(), 'complete unchanged verdict evidence')
    print('Scoped KMAC verdict: 32 LLVM wrappers across 16 configurations and 16 private assembly boundaries PASS')
    print('Only the normalized result returns; no raw difference load is allowed in forwarding wrappers')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not whole-verifier provenance, machine-code spill or native platform qualification; no build/runtime rerun')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
