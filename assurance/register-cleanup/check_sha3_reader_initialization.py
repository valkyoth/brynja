#!/usr/bin/env python3
"""Bind borrowed-reader entry to destination initialization before state checks."""
import argparse
import json
from pathlib import Path
import re
from types import SimpleNamespace

import check_sha3_borrowed_handle as borrowed
import check_secret_output_begin as initialization

reader = borrowed.reader
adapter = reader.adapter
comparison = reader.comparison
require = reader.require
SSA = reader.SSA


def inspect(function, begin, wipes):
    graph, _, _ = borrowed.inspect(function)
    _, edges, origin = adapter.routes.transfer.finish.graph_info(function)
    trace = SimpleNamespace(graph=graph, edges=edges)
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    args = comparison.arguments(header, symbol.end())
    require(all(arg.endswith(' ' + expected) for arg, expected in zip(args,
            ('%_0', '%self', '%destination.0', '%destination.1', '%0', '%1'))), 'original borrowed-reader entry arguments')
    start = graph['start']
    empty_test = re.fullmatch('(' + SSA + r') = icmp eq i64 %destination.1, 0', start[-2])
    require(empty_test is not None, 'only original zero length bypasses initialization')
    condition, empty, nonempty = adapter.shape.branch(trace, 'start')
    require(condition == empty_test[1] and empty != nonempty, 'nonempty path starts initialization')
    allocations = {}
    # Before initialization allow local metadata preparation only. No payload,
    # owner or lifecycle reads, escaped stores, branches or ordinary callees.
    for line in start[:-2]:
        allocated = re.fullmatch('(' + SSA + r') = alloca \[(\d+) x i8\], align (1|4|8)', line)
        if allocated:
            allocations[allocated[1]] = int(allocated[2])
            continue
        if re.fullmatch(SSA + r' = zext i1 %0 to i8', line):
            continue
        gep = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (\d+)', line)
        if gep:
            base, offset = origin(gep[1])
            require(base in allocations and 0 <= offset < allocations[base], 'local metadata address only')
            continue
        store = re.fullmatch(r'store (i8|i64) (' + SSA + r'), ptr (' + SSA + r'), align (1|4|8)', line)
        if store:
            base, offset = origin(store[3])
            width = 1 if store[1] == 'i8' else 8
            require(base in allocations and 0 <= offset <= allocations[base] - width, 'pre-init writes only bounded local metadata')
            continue
        name, params = adapter.routes.guard.call(line)
        require(name == 'llvm.lifetime.start.p0' and params in
                (['ptr nonnull %length'], ['i64 8', 'ptr nonnull %length'])
                and allocations.get('%length') == 8, 'only local lifetime marker before initialization')
    require(len(start) == 16 and len(allocations) == 8, 'complete local preparation inventory')
    block = graph[nonempty]
    require(len(block) == 5 and block[1].startswith('call void @'), 'closed initialization call and result decision')
    name, params = adapter.routes.guard.call(block[1])
    require(name == begin and len(params) == 3 and 'sret([32 x i8])' in params[0]
            and comparison.pointer(params[1]) == '%destination.0'
            and params[2].startswith('i64 ') and params[2].endswith(' %destination.1'), 'bound initializer gets entire original destination')
    result_match = re.search('(' + SSA + ')$', params[0])
    require(result_match is not None and allocations.get(result_match[1]) == 32, 'bounded local initialization result')
    result = result_match[1]

    def lifetime(line, kind, slot, width):
        name, params = adapter.routes.guard.call(line)
        require(name == 'llvm.lifetime.' + kind + '.p0' and params in
                (['ptr nonnull ' + slot], [f'i64 {width}', 'ptr nonnull ' + slot]), 'correct local lifetime boundary')

    lifetime(block[0], 'start', result, 32)
    load = re.fullmatch('(' + SSA + r') = load i8, ptr ' + re.escape(result) + ', align 8', block[2])
    require(load is not None, 'read actual initialization result discriminator')
    trunc = re.fullmatch('(' + SSA + r') = trunc nuw i8 ' + re.escape(load[1]) + ' to i1', block[3])
    tested, error, success = adapter.shape.branch(trace, nonempty)
    require(trunc is not None and tested == trunc[1] and error != success, 'initialization failure uses true discriminator edge')
    rejected = graph[error]
    require(len(rejected) == 9, 'closed initialization rejection path')
    lifetime(rejected[0], 'end', result, 32)
    active = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %self, i64 8', rejected[1])
    require(active is not None and rejected[2] == f'store i8 0, ptr {active[1]}, align 8', 'initialization failure terminates reader')
    owner = re.fullmatch('(' + SSA + r') = load ptr, ptr %self, align 8', rejected[3])
    require(owner is not None and rejected[4].startswith('tail call void @'), 'original owner cleanup on initialization rejection')
    wipe, params = adapter.routes.guard.call(rejected[4])
    require(wipe in wipes and len(params) == 1 and comparison.pointer(params[0]) == owner[1], 'bound wipe receives original reader owner')
    field = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %_0, i64 8', rejected[5])
    require(field is not None and rejected[6:8] == [f'store i8 4, ptr {field[1]}, align 8', 'store i64 2, ptr %_0, align 8'], 'value-free SecretMemory error')
    require(len(edges[error][0]) == 1, 'one rejection return')
    returning = edges[error][0][0]
    require(rejected[-1] == 'br label %' + returning and len(graph[returning]) == 2
            and graph[returning][-1] == 'ret void', 'rejection cannot enter squeeze or success work')
    lifetime(graph[returning][0], 'end', '%length', 8)
    # The empty branch is where the actual lifecycle read occurs. For nonempty
    # inputs there is no path to it without passing the initializer first.
    require(any(re.fullmatch(SSA + r' = load i8, ptr ' + SSA + ', align 8', line)
                and origin(re.search(r', ptr (' + SSA + ')', line)[1]) == ('%self', 8)
                for line in graph[empty]), 'lifecycle test follows initial empty/nonempty decision')
    return trace, (nonempty, error, success, returning), begin, wipe


def cases(record):
    begins = {}
    for function, zero in initialization.cases(record):
        initialization.inspect(function, zero)
        name = re.search(comparison.SYMBOL, function.splitlines()[0])[1]
        require(name not in begins or begins[name] == function, 'shared initializer symbol has identical retained definition')
        begins[name] = function
    for function, definitions, wipes in reader.cases(record):
        _, _, secret = reader.inspect(function, definitions, wipes)
        body = definitions[secret]
        calls = [adapter.routes.guard.call(line)[0] for lines in adapter.routes.guard.metadata.model.blocks(body).values()
                 for line in lines if line.startswith('call void @') and '26SecretRegionInitialization5begin' in line]
        require(len(calls) == 1 and calls[0] in begins, 'actual reader uses verified source-bound core initializer')
        yield body, calls[0], wipes


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*case) for case in cases(record)]
    require(len(checks) == 16 and before == comparison.capture.sources(), 'complete unchanged reader initialization matrix')
    print('Borrowed reader initialization: 16 source-bound entries; complete destination initialized before lifecycle/squeeze work PASS')
    print('Initialization rejection terminates the reader, requests original-owner wipe and returns only an error')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Entry ordering/rejection only; not later initialization transfer/drop, squeeze semantics or register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
