#!/usr/bin/env python3
"""Retained optimized SHA-3 output wrapping; not squeeze/callee erasure proof."""
import argparse
import json
from pathlib import Path
import re

import check_secret_output_finish as finish

comparison = finish.comparison
require = finish.require
SSA, LABEL = finish.SSA, finish.LABEL


def select(text):
    found = [body for name, body in comparison.definitions(text).items()
             if 'brynja_hash_sha3' in name and 'hardened6output13finish_secret' in name]
    require(len(found) == 1, 'unique retained SHA-3 output wrapper')
    return found[0]


def inspect(function, core):
    core_function = finish.select(core)
    finish.inspect(core_function)
    core_symbol = re.search(comparison.SYMBOL, core_function.splitlines()[0])[1]
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    arguments = comparison.arguments(header, symbol.end())
    require(re.search(r'\bvoid\s*$', header[:symbol.start()]) and len(arguments) == 2
            and arguments[0].endswith(' %_0') and arguments[1].endswith(' %initialization'), 'output wrapper ABI')
    graph, label = {}, None
    for raw in function.splitlines()[1:-1]:
        line = raw.strip()
        if not line or line.startswith(';'):
            continue
        block = re.fullmatch('(' + LABEL + r'):(?:\s*;.*)?', line)
        if block:
            label = block[1]
            require(label not in graph, 'unique output-wrapper block')
            graph[label] = []
        else:
            require(label is not None, 'output-wrapper block before instruction')
            graph[label].append(re.sub(r'(?:, ![\w.]+ !\d+)+$', '', line))
    require(len(graph) in (6, 7) and 'start' in graph, 'complete output-wrapper block inventory')
    covered = set()
    for scenario in ('empty', 'complete', 'incomplete', 'missing-region'):
        values = {'%_0': ('result', 0), '%initialization': ('input', 0)}
        payload = None if scenario == 'missing-region' else ('payload', 0)
        initialized = 'length' if scenario == 'complete' else 'initialized'
        memory = {('input', 0): 0 if scenario == 'empty' else 1,
                  ('input', 8): payload, ('input', 16): 'length', ('input', 24): initialized}
        bounds, stores = {'result': 24, 'input': 32}, {}
        calls, copies, seen, previous, label = 0, 0, set(), None, 'start'

        def address(operand, width):
            value = values.get(operand)
            require(isinstance(value, tuple) and value[0] in bounds
                    and 0 <= value[1] <= bounds[value[0]] - width, 'bounded wrapper descriptor address')
            return value

        while True:
            require(label in graph and label not in seen, 'acyclic complete wrapper path')
            seen.add(label)
            covered.add(label)
            successor, returned = None, False
            for line in graph[label]:
                require(successor is None and not returned, 'no operation after wrapper terminator')
                allocation = re.fullmatch('(' + SSA + r') = alloca \[24 x i8\], align 8', line)
                if allocation:
                    require(allocation[1] not in values, 'unique descriptor allocation')
                    values[allocation[1]] = allocation[1], 0
                    bounds[allocation[1]] = 24
                    continue
                gep = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (\d+)', line)
                if gep:
                    root, offset = address(gep[2], 1)
                    values[gep[1]] = root, offset + int(gep[3])
                    continue
                load = re.fullmatch('(' + SSA + r') = load (ptr|i64|i8), ptr (' + SSA + r'), align 8', line)
                if load:
                    source = address(load[3], 1 if load[2] == 'i8' else 8)
                    require(source in memory, 'load initialized descriptor field')
                    values[load[1]] = memory[source]
                    continue
                trunc = re.fullmatch('(' + SSA + r') = trunc nuw i(?:8|64) (' + SSA + r') to i1', line)
                if trunc:
                    value = values.get(trunc[2])
                    require(type(value) is int and value in (0, 1), 'branch uses option/result discriminant')
                    values[trunc[1]] = bool(value)
                    continue
                phi = re.fullmatch('(' + SSA + r') = phi i64 \[ (\d+), %(' + LABEL + r') \], \[ (\d+), %(' + LABEL + r') \]', line)
                if phi:
                    options = {phi[3]: int(phi[2]), phi[5]: int(phi[4])}
                    require(len(options) == 2 and previous in options, 'result discriminant predecessor')
                    values[phi[1]] = options[previous]
                    continue
                if 'call ' in line:
                    callee = re.search(comparison.SYMBOL, line)
                    require(callee is not None and line[:callee.start()] == 'call void ', 'plain descriptor wrapper call')
                    params = comparison.arguments(line, callee.end())
                    require(line.endswith(')'), 'plain wrapper call suffix')
                    if callee[1].startswith('llvm.lifetime.'):
                        require(callee[1] in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0')
                                and (len(params) == 1 or (len(params) == 2 and params[0] == 'i64 24')), 'reviewed lifetime intrinsic')
                        root, offset = address(comparison.pointer(params[-1]), 24)
                        require(root not in ('result', 'input') and offset == 0, 'whole local descriptor lifetime')
                    elif callee[1] == 'llvm.memcpy.p0.p0.i64':
                        require(len(params) == 4 and params[2:] == ['i64 24', 'i1 false'], 'exact initialization descriptor copy')
                        destination = address(comparison.pointer(params[0]), 24)
                        source = address(comparison.pointer(params[1]), 24)
                        require(source == ('input', 8) and destination[0] not in ('input', 'result') and destination[1] == 0, 'copy descriptor, never payload')
                        for offset in (0, 8, 16):
                            memory[destination[0], offset] = memory['input', 8 + offset]
                        copies += 1
                    else:
                        require(callee[1] == core_symbol and len(params) == 2, 'exact inspected ownership completion callee')
                        # Its output argument intentionally uses sret, unlike comparison.pointer.
                        output = re.search('(' + SSA + ')$', params[0])
                        require(output is not None and 'sret([24 x i8])' in params[0], 'completion result ABI')
                        destination = address(output[1], 24)
                        source = address(comparison.pointer(params[1]), 24)
                        require(destination[1] == source[1] == 0 and destination[0] != source[0]
                                and destination[0] not in ('input', 'result') and source[0] not in ('input', 'result'), 'separate local completion descriptors')
                        fields = [memory.get((source[0], offset)) for offset in (0, 8, 16)]
                        require(fields == [payload, 'length', initialized] and copies == 1, 'preserved original initialization fields')
                        # Summary bound above to the actual core LLVM checker.
                        success = fields[0] is not None and fields[1] == fields[2]
                        memory[destination[0], 0] = 0 if success else 1
                        if success:
                            memory[destination[0], 8] = fields[0]
                            memory[destination[0], 16] = fields[1]
                        calls += 1
                    continue
                store = re.fullmatch(r'store (i64|i8|ptr) (' + SSA + r'|\d+), ptr (' + SSA + r'), align 8', line)
                if store:
                    destination = address(store[3], 1 if store[1] == 'i8' else 8)
                    require(destination[0] == 'result' and destination not in stores, 'result fields written once')
                    value = int(store[2]) if store[2].isdecimal() else values.get(store[2])
                    require(value is not None, 'defined result value')
                    stores[destination] = (store[1], value)
                    continue
                branch = re.fullmatch(r'br i1 (' + SSA + r'), label %(' + LABEL + r'), label %(' + LABEL + ')', line)
                if branch:
                    condition = values.get(branch[1])
                    require(type(condition) is bool, 'defined wrapper branch')
                    successor = branch[2] if condition else branch[3]
                    continue
                branch = re.fullmatch(r'br label %(' + LABEL + ')', line)
                if branch:
                    successor = branch[1]
                    continue
                if line == 'ret void':
                    returned = True
                    continue
                raise ValueError('unreviewed output-wrapper instruction: ' + line)
            require(returned or successor is not None, 'terminated output-wrapper path')
            if returned:
                break
            previous, label = label, successor
        expected = {('result', 0): ('i64', 0)} if scenario == 'empty' else (
            {('result', 0): ('i64', 1), ('result', 8): ('ptr', payload), ('result', 16): ('i64', 'length')}
            if scenario == 'complete' else {('result', 0): ('i64', 2), ('result', 8): ('i8', 4)})
        require(stores == expected and calls == copies == (0 if scenario == 'empty' else 1), 'exact wrapped ownership/error result')
    require(covered == set(graph), 'all output-wrapper blocks covered')
    return len(graph)


def cases(record):
    comparison.validate_record(json.loads(record.read_text()), record.parent)
    for row in json.loads(record.read_text())['records']:
        if row['profile'] != 'release':
            continue
        def artifact(package):
            return next((record.parent / key).read_text() for key in row['artifacts']
                        if Path(key).name.startswith(package + '-') and key.endswith('.ll'))
        yield select(artifact('brynja_hash_sha3')), artifact('brynja_core')


def main(record):
    before = comparison.capture.sources()
    counts = [inspect(function, core) for function, core in cases(record)]
    require(len(counts) == 8 and sum(counts) == 52 and before == comparison.capture.sources(), 'complete unchanged wrapper matrix')
    print('SHA-3 output wrapping: eight optimized bodies, four metadata cases each, all 52 blocks PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not squeeze correctness, debug-code, spills or native qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
