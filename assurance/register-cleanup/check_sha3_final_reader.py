#!/usr/bin/env python3
"""Retained portable final-reader forwarding and destructor request paths."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_final_adapter as adapter

comparison = adapter.comparison
require = adapter.require
SSA = adapter.SSA


def inspect(function, definitions, wipes):
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    require(symbol is not None and header.startswith('define void @'), 'final reader return ABI')
    args = comparison.arguments(header, symbol.end())
    require(len(args) == 4 and 'sret([24 x i8])' in args[0]
            and args[1].startswith('ptr ') and args[2].startswith('i1 ') and args[3].startswith('ptr '), 'reader parameter ABI')
    parameters = [re.search('(' + SSA + ')$', arg) for arg in args]
    require(all(parameters) and len({match[1] for match in parameters}) == 4, 'distinct reader arguments')
    result, owner, active, output = [match[1] for match in parameters]
    graph, edges, origin = adapter.routes.transfer.finish.graph_info(function)
    require(len(graph) == 5, 'complete five-block reader boundary')
    lines = graph['start']
    require(lines[-2].startswith('invoke fastcc void @'), 'borrowed secret operation has explicit unwind edge')
    secret, params = adapter.routes.guard.call(lines[-2])
    require(secret in definitions and all(token in secret for token in ('hardened', 'in_place', 'xof', 'Borrowed', '6secret'))
            and 'accelerated' not in secret and len(params) == 6, 'defined portable borrowed secret callee')
    callee_header = definitions[secret].splitlines()[0]
    callee_symbol = re.search(comparison.SYMBOL, callee_header)
    callee_args = comparison.arguments(callee_header, callee_symbol.end())
    require(callee_header.startswith('define internal fastcc void @') and len(callee_args) == 6,
            'borrowed secret calling convention and arity')
    require(all(arg.startswith(kind + ' ') for arg, kind in zip(callee_args, ('ptr', 'ptr', 'ptr', 'i64', 'i1', 'i8'))),
            'borrowed secret argument types')
    handle = comparison.pointer(params[1])
    require(lines[0] == handle + ' = alloca [16 x i8], align 8', 'bounded local borrowed handle')
    values = {owner: 'original-owner', active: 'original-active'}
    stores = {}
    for line in lines[1:-2]:
        if re.fullmatch(SSA + r' = getelementptr inbounds nuw i8, ptr ' + SSA + r', i64 \d+', line):
            continue
        cast = re.fullmatch('(' + SSA + r') = zext i1 ' + re.escape(active) + ' to i8', line)
        if cast:
            values[cast[1]] = 'original-active-byte'
            continue
        load = re.fullmatch('(' + SSA + r') = load (ptr|i64|i8), ptr (' + SSA + r'), align 8', line)
        if load:
            base, offset = origin(load[3])
            require(base == output and (offset, load[2]) in ((0, 'ptr'), (8, 'i64'), (24, 'i8')),
                    'load only original output pointer/length/valid fields')
            values[load[1]] = ('output', offset)
            continue
        store = re.fullmatch(r'store (ptr|i8) (' + SSA + r'), ptr (' + SSA + r'), align 8', line)
        require(store is not None and store[2] in values, 'reviewed reader handle setup only')
        base, offset = origin(store[3])
        require(base == handle and offset not in stores, 'single bounded handle field write')
        stores[offset] = store[1], values[store[2]]
    require(stores == {0: ('ptr', 'original-owner'), 8: ('i8', 'original-active-byte')}, 'original owner and lifecycle stored in handle')
    integer = lambda arg, kind: re.fullmatch(kind + r'(?: noundef)? (' + SSA + ')', arg)
    length, valid = integer(params[3], 'i64'), integer(params[5], 'i8')
    require(comparison.pointer(params[0]) == result
            and values.get(comparison.pointer(params[2])) == ('output', 0)
            and length is not None and values.get(length[1]) == ('output', 8)
            and params[4] == 'i1 noundef zeroext true'
            and valid is not None and values.get(valid[1]) == ('output', 24),
            'borrowed secret receives original result, destination, length and final-bit mode')
    normal, cleanup = edges['start'][0]

    def wipe(label, prefix, invoke):
        block = graph[label]
        index = 2 if invoke else 0
        require(len(block) == index + 3 and (invoke or block[-1] == 'ret void'), 'closed cleanup request block')
        load = re.fullmatch('(' + SSA + r') = load ptr, ptr ' + re.escape(handle) + ', align 8', block[index])
        require(load is not None and block[index + 1].startswith(prefix), 'reload borrowed owner before cleanup request')
        name, arguments = adapter.routes.guard.call(block[index + 1])
        require(name in wipes and 'HardenedFips202Owner' in name and '4wipe' in name and len(arguments) == 1
                and comparison.pointer(arguments[0]) == load[1], 'bound owner wipe uses reloaded handle pointer')
        return name

    normal_wipe = wipe(normal, 'tail call void @', False)
    unwind_wipe = wipe(cleanup, 'invoke void @', True)
    require(normal_wipe == unwind_wipe, 'same cleanup request on normal and unwind paths')
    landing = re.fullmatch('(' + SSA + r') = landingpad \{ ptr, i32 }', graph[cleanup][0])
    require(landing is not None and graph[cleanup][1] == 'cleanup', 'recoverable secret-call unwind')
    resume, terminate = edges[cleanup][0]
    require(graph[resume] == ['resume { ptr, i32 } ' + landing[1]], 'resume original exception only after cleanup returns')
    terminal = graph[terminate]
    require(len(terminal) == 4 and re.fullmatch(SSA + r' = landingpad \{ ptr, i32 }', terminal[0])
            and terminal[1] == 'filter [0 x ptr] zeroinitializer' and terminal[-1] == 'unreachable', 'double-panic termination boundary')
    name, arguments = adapter.routes.guard.call(terminal[2])
    require(terminal[2].startswith('tail call void @') and '4core' in name and '16panic_in_cleanup' in name
            and arguments == [''], 'only identified double-panic abort is excluded')
    require(set(graph) == {'start', normal, cleanup, resume, terminate}, 'all reader blocks classified')
    return graph, (normal, cleanup, resume, terminate), secret


def cases(record):
    for row, caller, callees in adapter.cases(record):
        trace = adapter.inspect(caller, callees)
        label, index, *_ = trace.adapter_details
        called, _ = adapter.routes.guard.call(trace.graph[label][index])
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'unique validated reader artifact')
        text = paths[0].read_text()
        definitions = comparison.definitions(text)
        if called not in definitions:
            aliases = re.findall(r'^@' + re.escape(called) + r' = unnamed_addr alias void \(ptr, ptr, i1, ptr\), ptr @([^ ]+)$', text, re.M)
            require(len(aliases) == 1 and aliases[0] in definitions, 'previously validated final-reader alias resolves to a body')
            called = aliases[0]
        yield definitions[called], definitions, adapter.routes.early.state_symbols(text)


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(function, definitions, wipes) for function, definitions, wipes in cases(record)]
    require(len(checks) == 16 and sum(len(graph) for graph, _, _ in checks) == 80
            and before == comparison.capture.sources(), 'complete unchanged portable final-reader matrix')
    print('Portable final reader: 16 bodies, all 80 blocks, 32 normal/unwind cleanup request sites PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Forwarding and cleanup requests only; borrowed-callee handle preservation, wipe contents, spills and abort cleanup are separate contracts')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
