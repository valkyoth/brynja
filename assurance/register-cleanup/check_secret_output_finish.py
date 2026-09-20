#!/usr/bin/env python3
"""Inspect retained optimized output ownership handoff, not whole-callee erasure."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_verify_comparisons as comparison

require = comparison.require
SSA = r'%[-.$\w]+'
LABEL = r'(?:"[^"]+"|[-.$\w]+)'


def select(text):
    found = [body for name, body in comparison.definitions(text).items()
             if 'SecretRegionInitialization6finish' in name]
    require(len(found) == 1, 'unique initialization completion function')
    return found[0]


def blocks(function):
    result, label = {}, None
    for raw in function.splitlines()[1:-1]:
        line = raw.strip()
        if not line or line.startswith(';'):
            continue
        match = re.match('(' + LABEL + r'):(?:\s*;.*)?$', line)
        if match:
            label = match[1]
            require(label not in result, 'unique handoff block')
            result[label] = []
        else:
            require(label is not None, 'instruction requires block')
            result[label].append(re.sub(r'(?:, ![\w.]+ !\d+)+$', '', line))
    require(len(result) == 6 and 'start' in result, 'six-block completion inventory')
    return result


def inspect(function):
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    require(re.search(r'\bvoid\s*$', header[:symbol.start()]), 'completion returns descriptor by output pointer')
    arguments = comparison.arguments(header, symbol.end())
    require(len(arguments) == 2 and arguments[0].endswith(' %_0')
            and 'sret([24 x i8])' in arguments[0] and arguments[1].endswith(' %self'), 'completion ABI')
    graph = blocks(function)
    covered = set()
    for scenario in ('absent', 'complete', 'incomplete'):
        values = {'%self': ('self', 0), '%_0': ('result', 0)}
        pointer = None if scenario == 'absent' else ('payload', 0)
        initialized = 'length' if scenario == 'complete' else 'initialized'
        memory = {('self', 0): pointer, ('self', 8): 'length', ('self', 16): initialized}
        stores, wipes, seen, label = {}, [], set(), 'start'
        while True:
            require(label in graph and label not in seen, 'acyclic complete handoff path')
            seen.add(label)
            covered.add(label)
            successor, returned = None, False
            for line in graph[label]:
                require(successor is None and not returned, 'no work after block terminator')
                gep = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (\d+)', line)
                if gep:
                    require(gep[1] not in values and gep[2] in values, 'defined unique address')
                    base = values[gep[2]]
                    require(isinstance(base, tuple) and base[0] in ('self', 'result'), 'descriptor address only')
                    values[gep[1]] = base[0], base[1] + int(gep[3])
                    continue
                load = re.fullmatch('(' + SSA + r') = load (ptr|i64), ptr (' + SSA + r'), align 8', line)
                if load:
                    address = values.get(load[3])
                    require(load[1] not in values and address in memory, 'load only original descriptor fields')
                    require((load[2], address) in (('ptr', ('self', 0)), ('i64', ('self', 8)), ('i64', ('self', 16))), 'typed descriptor fields')
                    values[load[1]] = memory[address]
                    continue
                compare = re.fullmatch('(' + SSA + r') = icmp eq (ptr|i64) (' + SSA + r'), (' + SSA + r'|null)', line)
                if compare:
                    require(compare[1] not in values and compare[3] in values, 'comparison SSA')
                    left = values[compare[3]]
                    require(compare[4] == 'null' or compare[4] in values, 'comparison operand')
                    right = None if compare[4] == 'null' else values[compare[4]]
                    if compare[2] == 'ptr':
                        require(compare[4] == 'null' and left == pointer, 'presence comparison only')
                    else:
                        require(left in ('length', 'initialized') and right in ('length', 'initialized'), 'initialization length comparison only')
                    values[compare[1]] = left == right
                    continue
                store = re.fullmatch(r'store (ptr|i8|i64) (' + SSA + r'|null|\d+), ptr (' + SSA + r'), align (1|8)', line)
                if store:
                    address = values.get(store[3])
                    operand = store[2]
                    value = None if operand == 'null' else int(operand) if operand.isdecimal() else values.get(operand)
                    require(not operand.startswith('%') or operand in values, 'defined stored descriptor value')
                    if address == ('self', 0):
                        require(scenario == 'complete' and store[1] == 'ptr' and value is None, 'only consumed-owner nulling allowed')
                    else:
                        allowed = {('result', 0): 'i8', ('result', 1): 'i8', ('result', 8): 'ptr', ('result', 16): 'i64'}
                        require(address in allowed and store[1] == allowed[address] and address not in stores, 'unique correctly typed result field')
                        stores[address] = value
                    continue
                if 'call ' in line:
                    callee = re.search(comparison.SYMBOL, line)
                    require(callee is not None and 'secret_memory_volatile23zeroize_region_volatile' in callee[1], 'only volatile cleanup callee')
                    require(re.fullmatch(r'tail call fastcc void ', line[:callee.start()]), 'normal cleanup call ABI')
                    require(re.fullmatch(r'(?: #\d+)?', line[line.rfind(')') + 1:]), 'plain cleanup call suffix')
                    params = comparison.arguments(line, callee.end())
                    require(len(params) == 2, 'complete cleanup argument list')
                    data = comparison.pointer(params[0])
                    length = re.fullmatch(r'i64 (?:noundef )?(' + SSA + ')', params[1])
                    require(length is not None and data in values and length[1] in values, 'defined cleanup arguments')
                    wipes.append((values[data], values[length[1]]))
                    continue
                branch = re.fullmatch(r'br i1 (' + SSA + r'), label %(' + LABEL + r'), label %(' + LABEL + ')', line)
                if branch:
                    condition = values.get(branch[1])
                    require(type(condition) is bool, 'branch depends on reviewed metadata comparison')
                    successor = branch[2] if condition else branch[3]
                    continue
                branch = re.fullmatch(r'br label %(' + LABEL + ')', line)
                if branch:
                    successor = branch[1]
                    continue
                if line == 'ret void':
                    returned = True
                    continue
                raise ValueError('unreviewed ownership-handoff instruction: ' + line)
            require(returned or successor is not None, 'terminated handoff block')
            if returned:
                break
            label = successor
        expected = {('result', 0): 0, ('result', 8): pointer, ('result', 16): 'length'} if scenario == 'complete' else {('result', 0): 1, ('result', 1): 3}
        require(stores == expected, 'exact ownership or value-free error result')
        require(wipes == ([(pointer, 'length')] if scenario == 'incomplete' else []), 'failed initialization clears original full region exactly once')
    require(covered == set(graph), 'all completion blocks inspected')


def cases(record):
    for row, _, core, _ in comparison.cases(record):
        if row['profile'] == 'release':
            yield select(core)


def main(record):
    before = comparison.capture.sources()
    count = 0
    for function in cases(record):
        inspect(function)
        count += 1
    require(count == 8 and before == comparison.capture.sources(), 'complete unchanged optimized matrix')
    print('Secret output completion: eight optimized bodies, three metadata cases each, all 48 blocks PASS')
    print('Success returns original pointer/length; incomplete input requests full original-region clearing')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not byte-production correctness, volatile callee completion, spills, or platform qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
