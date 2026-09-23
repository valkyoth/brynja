#!/usr/bin/env python3
"""Retained initialization destructor clears the entire still-owned region."""
import argparse
import json
from pathlib import Path
import re
from types import SimpleNamespace

import check_secret_output_begin as begin

adapter = begin.adapter
comparison = begin.comparison
require = begin.require
SSA = begin.SSA


def select(core):
    found = [(name, body) for name, body in comparison.definitions(core).items()
             if 'SecretRegionInitialization' in name and '4drop' in name]
    require(len(found) == 1, 'unique defined initialization destructor')
    return found[0]


def inspect(function, zero):
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    require(symbol is not None and header.startswith('define void @'), 'destructor returns no value')
    params = comparison.arguments(header, symbol.end())
    require(len(params) == 1 and params[0].startswith('ptr noalias ')
            and 'dereferenceable(24)' in params[0] and params[0].endswith(' %self'), 'exclusive complete initialization handle')
    graph, edges, _ = adapter.routes.transfer.finish.graph_info(function)
    require(len(graph) == 3 and len(graph['start']) == 3, 'closed three-block destructor')
    start = graph['start']
    pointer = re.fullmatch('(' + SSA + r') = load ptr, ptr %self, align 8', start[0])
    require(pointer is not None, 'load original optional region pointer')
    tested = re.fullmatch('(' + SSA + r') = icmp eq ptr ' + re.escape(pointer[1]) + ', null', start[1])
    condition, absent, present = adapter.shape.branch(SimpleNamespace(graph=graph), 'start')
    require(tested is not None and condition == tested[1] and absent != present,
            'only absent ownership skips cleanup')
    require(graph[absent] == ['ret void'], 'absent ownership has no payload work')
    block = graph[present]
    require(len(block) == 4, 'only length load, bound cleanup and return')
    field = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %self, i64 8', block[0])
    require(field is not None, 'full region length field, not initialized prefix')
    length = re.fullmatch('(' + SSA + r') = load i64, ptr ' + re.escape(field[1]) + ', align 8', block[1])
    require(length is not None and block[2].startswith('tail call fastcc void @'), 'load complete stored region length')
    name, args = adapter.routes.guard.call(block[2])
    require(name == zero and len(args) == 2 and comparison.pointer(args[0]) == pointer[1]
            and re.fullmatch(r'i64(?: noundef)? ' + re.escape(length[1]), args[1]),
            'defined volatile callee receives original pointer and full length')
    require(block[-1] == 'br label %' + absent and tuple(edges[present][0]) == (absent,)
            and set(graph) == {'start', present, absent}, 'return only after the full-region cleanup call')
    return graph, (present, absent)


def cases(record):
    for row, _, core, assembly in comparison.cases(record):
        if row['profile'] != 'release':
            continue
        _, zero = begin.select(core)
        name, body = select(core)
        begin.clearing.llvm.inspect(begin.clearing.llvm.select(core))
        emitted = begin.clearing.select(assembly)
        require(emitted.splitlines()[0] == zero + ':', 'destructor cleanup bound to matching emitted symbol')
        begin.clearing.inspect(emitted, row['target'].startswith('aarch64'))
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'unique source-bound SHA-3 caller artifact')
        # Confirm this exact external destructor is referenced by the borrowed
        # reader, not merely an unrelated exported core function. Call ordering
        # and the descriptor transferred to it remain separate caller checks.
        sha3 = comparison.definitions(paths[0].read_text())
        callers = [f for n, f in sha3.items() if 'Borrowed' in n and '6secret' in n
                   and 'in_place' in n and 'accelerated' not in n]
        require(len(callers) == 2 and all(any(
            ('call void @' in line or 'invoke void @' in line)
            and adapter.routes.guard.call(line)[0] == name
            for line in f.splitlines() if 'SecretRegionInitialization' in line and '4drop' in line)
            for f in callers), 'both borrowed reader strengths reference the actual destructor')
        yield body, zero


def main(record):
    before = comparison.capture.sources()
    checked = [inspect(*case) for case in cases(record)]
    require(len(checked) == 8 and before == comparison.capture.sources(), 'complete unchanged optimized destructor matrix')
    print('Secret initialization drop: 8 optimized bodies, all 24 blocks; full region rather than written prefix cleared PASS')
    print('Actual borrowed-reader references, volatile callee model and matching assembly checked')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Destructor boundary only; not caller descriptor transfer/cleanup coverage, abort or register/spill erasure; Arm remains QEMU')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
