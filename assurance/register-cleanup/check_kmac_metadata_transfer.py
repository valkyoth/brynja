#!/usr/bin/env python3
"""Link retained KMAC finish metadata stores to verifier extraction."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_finish_cleanup as finish

early = finish.early
comparison = finish.comparison
guard = finish.guard
require = finish.require
SSA = finish.SSA


def discriminator(graph, edges, label, success, size):
    lines = graph[label]
    branch = re.fullmatch(r'br i1 (' + SSA + r'), label %(' + guard.LABEL + r'), label %(' + guard.LABEL + ')', lines[-1])
    require(branch is not None and branch[3] == success and branch[2] != success,
            'success follows the non-error discriminator edge')
    kind, invalid = ('i8', '2') if size == 24 else ('ptr', 'null')
    matches = [re.fullmatch(re.escape(branch[1]) + r' = icmp eq ' + kind + ' (' + SSA + '), ' + invalid, line)
               for line in lines[:-1] if line.startswith(branch[1] + ' = ')]
    require(len(matches) == 1 and matches[0] is not None, 'exact retained result discriminator')
    return kind, matches[0][1], edges[label][0][0]


def stores(graph, origin):
    result = []
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            if not line.startswith('store '):
                continue
            match = re.fullmatch(r'store (ptr|i\d+) (.+), ptr (' + SSA + r'), align (\d+)', line)
            require(match is not None, 'reviewed scalar/descriptor store form')
            kind, value, destination = match[1], match[2], match[3]
            width = 8 if kind == 'ptr' else int(kind[1:]) // 8
            require(width > 0 and (kind == 'ptr' or int(kind[1:]) % 8 == 0), 'whole-byte descriptor store')
            base, offset = origin(destination)
            require(base != '%self' or offset >= 8, 'original metadata pointer field is not overwritten')
            if base == '%_0':
                result.append((label, index, offset, width, kind, value))
    return result


def transfer(function, state_callees):
    graph, edges, origin = finish.graph_info(function)
    size_match = re.search(r'dereferenceable\((24|32)\) %_0', function.splitlines()[0])
    require(size_match is not None, 'bounded success-result descriptor')
    size = int(size_match[1])
    output_stores = stores(graph, origin)
    require(all(0 <= offset and offset + width <= size for _, _, offset, width, _, _ in output_stores), 'bounded result stores')
    metadata = [entry for entry in output_stores if entry[2] < size and entry[2] + entry[3] > size - 8]
    require(len(metadata) == 1, 'one unambiguous metadata output store')
    label, index, offset, width, kind, owner = metadata[0]
    require((offset, width, kind) == (size - 8, 8, 'ptr') and re.fullmatch(SSA, owner), 'exact metadata pointer field')
    require(owner + ' = load ptr, ptr %self, align 8' in graph[label][:index], 'transfer the original metadata pointer')
    writes = [entry for entry in output_stores if entry[0] == label]
    shape = [(entry[2], entry[3], entry[4]) for entry in writes]
    expected = ([(0, 8, 'ptr'), (8, 1, 'i8'), (16, 8, 'ptr')] if size == 24 else
                [(0, 8, 'ptr'), (8, 8, 'i64'), (16, 8, 'i64'), (24, 8, 'ptr')])
    split = [(0, 8, 'ptr'), (8, 1, 'i8'), (9, 7, 'i56'), (16, 8, 'i64'), (24, 8, 'ptr')]
    require(shape == expected or size == 32 and shape == split, 'reviewed nonoverlapping reader/metadata fields')
    predecessors = [source for source in graph if label in edges[source][0]]
    require(len(predecessors) == 1, 'unique success-result decision')
    decision = predecessors[0]
    _, value, error = discriminator(graph, edges, decision, label, size)
    require(error in finish.errors(function)[0], 'opposite edge writes a recognized error result')
    discriminator_store = next(entry for entry in writes if entry[2] == (8 if size == 24 else 0))
    require(discriminator_store[5] == value, 'result carries the discriminator that was tested')

    # Small normal-return slice only. No writes may follow the transfer block;
    # the only permitted non-intrinsic call drops the remaining state field.
    todo, seen, state_calls, returns = [label], set(), set(), set()
    while todo:
        current = todo.pop()
        require(current not in seen, 'acyclic success-transfer slice without reconvergent duplicate work')
        seen.add(current)
        lines = graph[current]
        for position, line in enumerate(lines):
            if line.startswith('store '):
                require(current == label and any(entry[1] == position for entry in writes), 'only reviewed output stores before return')
            elif re.match(r'(?:' + SSA + r' = )?(?:tail )?(?:call|invoke) ', line):
                name, args = guard.call(line)
                if name == 'llvm.assume':
                    require(current == label and re.fullmatch(r'call void @llvm.assume\(i1 ' + SSA + r'\)', line), 'non-mutating success assumption')
                else:
                    require(name in state_callees and line.startswith('call void @') and len(args) == 1, 'bound remaining-state normal call')
                    pointer = comparison.pointer(args[0])
                    if 'HardenedFips202Owner' in name:
                        loads = [re.fullmatch(re.escape(pointer) + r' = load ptr, ptr (' + SSA + r'), align 8', previous)
                                 for previous in lines[:position] if previous.startswith(pointer + ' = ')]
                        require(len(loads) == 1 and loads[0] is not None and origin(loads[0][1]) == ('%self', 8), 'drop original portable state')
                    else:
                        require(origin(pointer) == ('%self', 8), 'drop original accelerated state')
                    state_calls.add((current, position))
            else:
                require(re.match(r'(?:(?:' + SSA + r' = )?(?:getelementptr|load|icmp|lshr|trunc)\b|(?:br|ret)\b)', line),
                        'reviewed normal-transfer instruction: ' + line)
        targets, terminal = edges[current]
        if terminal:
            require(terminal == 'return' and lines[-1] == 'ret void', 'normal void result return')
            returns.add(current)
        # A diamond legitimately shares its return block. It is checked once;
        # cycles are excluded separately by the exact three-block shape below.
        todo.extend(target for target in targets if target not in seen and target not in todo)
    require(len(seen) == 3 and len(returns) == len(state_calls) == 1, 'complete success transfer/drop/return diamond')
    exit_label = next(iter(returns))
    drop_label = next(iter(state_calls))[0]
    require(set(edges[label][0]) == {exit_label, drop_label} and edges[drop_label][0] == (exit_label,), 'both success paths return without further writes')
    return size, label, decision, owner, len(writes)


def extraction_path(graph, origin, gate, extraction, owner, slot):
    allocations = {}
    for line in graph['start']:
        match = re.fullmatch('(' + SSA + r') = alloca \[(\d+) x i8\], align \d+', line)
        if match:
            allocations[match[1]] = int(match[2])
    call_index = next(i for i, line in enumerate(graph[gate]) if line.startswith('call fastcc void @') and '6finish' in line)
    load_index = next(i for i, line in enumerate(graph[extraction]) if line.startswith(owner + ' = '))
    for line in graph[gate][call_index + 1:] + graph[extraction][:load_index + 1]:
        if re.match(r'(?:' + SSA + r' = )?(?:getelementptr|load|icmp|br)\b', line):
            continue
        require(line.startswith('call void @'), 'no result mutation between finish and metadata extraction')
        name, args = guard.call(line)
        if name == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[2:] == ['i64 15', 'i1 false'], 'only reviewed reader descriptor copy')
            target, offset = origin(comparison.pointer(args[0]))
            require(target != slot and target in allocations and 0 <= offset and offset + 15 <= allocations[target]
                    and origin(comparison.pointer(args[1])) == (slot, 9), 'reader copy cannot overwrite result or cross its metadata field')
        else:
            require(name in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0') and len(args) in (1, 2), 'lifetime markers only')
            pointer = comparison.pointer(args[-1])
            require(pointer != slot and pointer in allocations, 'result remains live until metadata extraction')


def inspect(verifier, function, names, defined, state_callees):
    size, label, decision, owner, writes = transfer(function, state_callees)
    graph, edges, _, origin, gate = early.prelude(verifier, names, defined)
    _, _, _, _, _, extracted_owner, extraction = early.optimized.inventory(verifier, names, defined)
    calls = [guard.call(line) for line in graph[gate] if line.startswith('call fastcc void @') and '6finish' in line]
    symbol = re.search(comparison.SYMBOL, function.splitlines()[0])
    require(len(calls) == 1 and calls[0][0] == symbol[1], 'caller uses this exact finish definition')
    slot = comparison.pointer(calls[0][1][0])
    require(slot + f' = alloca [{size} x i8], align 8' in graph['start'], 'caller and callee agree on result descriptor size')
    kind, value, _ = discriminator(graph, edges, gate, extraction, size)
    load = next((re.fullmatch(re.escape(value) + r' = load ' + kind + ', ptr (' + SSA + r'), align 8', line)
                 for line in graph[gate] if line.startswith(value + ' = ')), None)
    require(load is not None and origin(load[1]) == (slot, 8 if size == 24 else 0), 'caller tests the returned result discriminator')
    extraction_path(graph, origin, gate, extraction, extracted_owner, slot)
    # The previous inventory also checks extraction at the matching last field,
    # and binds that owner to the later difference predicate at metadata +65.
    return writes


def cases(record):
    for row, names, defined, state_callees, verifiers in early.cases(record):
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_mac_kmac-') and path.endswith('.ll')]
        require(len(paths) == 1, 'unique validated KMAC artifact')
        functions = comparison.definitions(paths[0].read_text())
        for verifier in verifiers:
            graph, _, _, _, gate = early.prelude(verifier, names, defined)
            callees = [guard.call(line)[0] for line in graph[gate] if line.startswith('call fastcc void @') and '6finish' in line]
            require(len(callees) == 1 and callees[0] in functions, 'bound actual finish definition')
            yield row, verifier, functions[callees[0]], names, defined, state_callees


def main(record):
    before = comparison.capture.sources()
    count = writes = 0
    for _, verifier, function, names, defined, state_callees in cases(record):
        writes += inspect(verifier, function, names, defined, state_callees)
        count += 1
    require((count, writes) == (24, 84) and before == comparison.capture.sources(), 'complete unchanged metadata transfer matrix')
    print(f'KMAC metadata transfer: {count} linked finish/verifier pairs, {writes} result-field stores and 48 matching discriminator decisions PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not reader-content correctness, prior callee/alias effects, comparison-byte provenance, implicit unwinds, machine spills or native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
