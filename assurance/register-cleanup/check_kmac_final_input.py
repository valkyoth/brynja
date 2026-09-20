#!/usr/bin/env python3
"""Retained KMAC final-reader input forwarding, not constructor semantics."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_final_adapter as adapter

comparison = adapter.comparison
require = adapter.require
SSA = adapter.SSA


def constructor(text):
    bodies = [body for name, body in comparison.definitions(text).items()
              if 'brynja_hash_sha3' in name and '13Fips202Output3new' in name]
    require(len(bodies) == 1, 'unique defined output constructor')
    header = bodies[0].splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    args = comparison.arguments(header, symbol.end())
    require(header.startswith('define void @') and len(args) == 4
            and 'sret([32 x i8])' in args[0] and args[1].startswith('ptr ')
            and args[2].startswith('i64 ') and args[3].startswith('i8 '), 'defined constructor ABI')
    return symbol[1]


def inspect(function, callees, new):
    trace = adapter.inspect(function, callees)
    graph = trace.graph
    reader, reader_index, _, _, _, _ = trace.adapter_details
    start = graph['start']
    require(len(start) >= 3 and start[-2].startswith('invoke void @'), 'constructor invoked at adapter entry')
    name, args = adapter.routes.guard.call(start[-2])
    require(name == new and len(args) == 4 and 'sret([32 x i8])' in args[0]
            and comparison.pointer(args[1]) == '%output.0'
            and args[2:] == ['i64 noundef %output.1', 'i8 noundef %valid'],
            'constructor receives original destination, length and valid-bit count')
    result = re.search('(' + SSA + ')$', args[0])
    require(result is not None, 'bounded constructor result slot')
    result = result[1]
    allocations, addresses, memory, loaded, ended = {}, {}, {}, {}, set()

    def address(value, width):
        require(value in addresses, 'known local descriptor address')
        base, offset = addresses[value]
        require(base not in ended and 0 <= offset <= allocations[base] - width,
                'live bounded descriptor access')
        return base, offset

    def lifetime(line, operation):
        name, params = adapter.routes.guard.call(line)
        require(name == 'llvm.lifetime.' + operation + '.p0' and len(params) in (1, 2), 'reviewed lifetime only')
        base, offset = address(comparison.pointer(params[-1]), 1)
        require(offset == 0 and (len(params) == 1 or params[0] == 'i64 ' + str(allocations[base])),
                'whole local descriptor lifetime')
        if operation == 'end':
            require(base == result, 'only consumed constructor result ends before reader')
            ended.add(base)

    for line in start[:-2]:
        match = re.fullmatch('(' + SSA + r') = alloca \[(\d+) x i8\], align (4|8)', line)
        if match:
            require(match[1] not in allocations and int(match[2]) in (23, 24, 32), 'reviewed local descriptor size')
            allocations[match[1]] = int(match[2])
            addresses[match[1]] = match[1], 0
        else:
            require(line.startswith('call void @llvm.lifetime.start.p0('), 'no work before constructor except local lifetimes')
            lifetime(line, 'start')
    require(result in allocations and allocations[result] == 32, 'constructor writes complete local descriptor')
    # Opaque byte provenance, including padding; this neither interprets nor
    # promises initialization of padding in the actual constructor result.
    for offset in range(32):
        memory[result, offset] = ('constructor', offset)
    decision = trace.edges['start'][0][0]
    lines = graph[decision]
    require(len(lines) == 3, 'closed constructor-result decision')
    load = re.fullmatch('(' + SSA + r') = load ptr, ptr ' + re.escape(result) + ', align 8', lines[0])
    require(load is not None, 'constructor discriminator from actual result')
    loaded[load[1]] = tuple(memory[result, offset] for offset in range(8))
    condition, error, accepted = adapter.shape.branch(trace, decision)
    require(lines[1] == condition + ' = icmp eq ptr ' + load[1] + ', null'
            and accepted == reader and error != reader, 'only non-null constructor result reaches reader')
    require([label for label in graph if decision in trace.edges[label][0]] == ['start'], 'unique constructor result predecessor')
    adapter.shape.unreachable(trace, 'start', {reader}, (decision, reader))
    adapter.shape.unreachable(trace, error, {reader, 'start'})

    copies = stores = 0
    for line in graph[reader][:reader_index]:
        gep = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (\d+)', line)
        if gep:
            base, offset = address(gep[2], 1)
            addresses[gep[1]] = base, offset + int(gep[3])
            address(gep[1], 1)
            continue
        load = re.fullmatch('(' + SSA + r') = load (ptr|i8), ptr (' + SSA + r'), align 8', line)
        if load:
            width = 8 if load[2] == 'ptr' else 1
            base, offset = address(load[3], width)
            require(all((base, offset + i) in memory for i in range(width)), 'load forwarded descriptor bytes')
            loaded[load[1]] = tuple(memory[base, offset + i] for i in range(width))
            continue
        store = re.fullmatch(r'store (ptr|i8) (' + SSA + r'), ptr (' + SSA + r'), align 8', line)
        if store:
            width = 8 if store[1] == 'ptr' else 1
            base, offset = address(store[3], width)
            require(base != result and store[2] in loaded and len(loaded[store[2]]) == width, 'exact loaded descriptor field store')
            for i, byte in enumerate(loaded[store[2]]):
                require((base, offset + i) not in memory, 'descriptor byte written once')
                memory[base, offset + i] = byte
            stores += 1
            continue
        require(line.startswith('call void @'), 'reviewed descriptor-forwarding instruction: ' + line)
        name, params = adapter.routes.guard.call(line)
        if name == 'llvm.lifetime.end.p0':
            lifetime(line, 'end')
            continue
        require(name == 'llvm.memcpy.p0.p0.i64' and len(params) == 4 and params[2:] == ['i64 23', 'i1 false'], 'exact descriptor tail copy')
        destination, dest_offset = address(comparison.pointer(params[0]), 23)
        source, src_offset = address(comparison.pointer(params[1]), 23)
        require(destination != result and source != destination, 'distinct descriptor copy regions')
        for i in range(23):
            require((source, src_offset + i) in memory and (destination, dest_offset + i) not in memory,
                    'defined source and single descriptor-tail write')
            memory[destination, dest_offset + i] = memory[source, src_offset + i]
        copies += 1
    _, reader_args = adapter.routes.guard.call(graph[reader][reader_index])
    destination, offset = address(comparison.pointer(reader_args[3]), 32)
    require(offset == 0 and destination != result and allocations[destination] == 32
            and tuple(memory.get((destination, i)) for i in range(32)) == tuple(('constructor', i) for i in range(32)),
            'reader receives the complete unmodified constructor descriptor')
    require(ended == {result} and copies in (1, 2) and stores == 2, 'complete reviewed descriptor transfer')
    trace.input_details = (result, decision, error, reader, reader_index)
    trace.input_copies = copies
    return trace


def cases(record):
    for row, function, callees in adapter.cases(record):
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'unique validated constructor artifact')
        yield function, callees, constructor(paths[0].read_text())


def main(record):
    before = comparison.capture.sources()
    traces = [inspect(function, callees, new) for function, callees, new in cases(record)]
    require(len(traces) == 16 and sum(t.input_copies for t in traces) == 24
            and comparison.capture.sources() == before, 'complete unchanged input-forwarding matrix')
    print('KMAC final input: 16 adapters, 24 descriptor-tail copies, original constructor arguments PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Opaque descriptor forwarding only; not constructor/reader semantics, padding initialization or register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
