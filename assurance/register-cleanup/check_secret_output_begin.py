#!/usr/bin/env python3
"""Retained secret-output initialization: clear before returning ownership."""
import argparse
import json
from pathlib import Path
import re
from types import SimpleNamespace

import check_kmac_final_adapter as adapter
import check_volatile_clear_assembly as clearing

comparison = adapter.comparison
require = adapter.require
SSA = adapter.SSA


def select(core):
    definitions = comparison.definitions(core)
    begin = [body for name, body in definitions.items() if '26SecretRegionInitialization5begin' in name]
    zero = [name for name in definitions if 'secret_memory_volatile23zeroize_region_volatile' in name]
    require(len(begin) == len(zero) == 1, 'unique defined initialization and volatile clearing')
    return begin[0], zero[0]


def inspect(function, zero):
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    require(symbol is not None and header.startswith('define void @'), 'initialization return ABI')
    args = comparison.arguments(header, symbol.end())
    require(len(args) == 3 and 'sret([32 x i8])' in args[0]
            and args[0].endswith(' %_0') and args[1].endswith(' %region.0')
            and args[2].startswith('i64 ') and args[2].endswith(' %region.1'), 'original initialization parameter identities')
    graph, edges, _ = adapter.routes.transfer.finish.graph_info(function)
    require(len(graph) == 4 and len(graph['start']) == 2, 'complete four-block initialization')
    test = re.fullmatch('(' + SSA + r') = icmp eq i64 %region.1, 0', graph['start'][0])
    require(test is not None, 'only empty original destination skips clearing')
    condition, empty, nonempty = adapter.shape.branch(SimpleNamespace(graph=graph), 'start')
    require(condition == test[1] and empty != nonempty, 'correct empty/nonempty branch direction')
    error, success = graph[empty], graph[nonempty]
    require(len(error) == 3 and len(success) == 8, 'closed initialization result paths')

    def field(line, offset):
        match = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %_0, i64 ' + str(offset), line)
        require(match is not None, 'original result field offset')
        return match[1]

    failure_field = field(error[0], 1)
    require(error[1] == f'store i8 0, ptr {failure_field}, align 1', 'empty-region error identity')
    name, params = adapter.routes.guard.call(success[0])
    require(success[0].startswith('tail call fastcc void @') and name == zero and len(params) == 2
            and comparison.pointer(params[0]) == '%region.0'
            and params[1].startswith('i64 ') and params[1].endswith(' %region.1'),
            'actual volatile callee clears original full destination before ownership stores')
    for index, offset, kind, value in ((1, 8, 'ptr', '%region.0'), (3, 16, 'i64', '%region.1'), (5, 24, 'i64', '0')):
        address = field(success[index], offset)
        require(success[index + 1] == f'store {kind} {value}, ptr {address}, align 8',
                'original pointer/length and zero initialized-byte count')
    require(edges[empty][0] == edges[nonempty][0] and len(edges[empty][0]) == 1,
            'both paths reach one shared result return')
    returning = edges[empty][0][0]
    require(error[-1] == success[-1] == 'br label %' + returning, 'no other initialization exits')
    final = graph[returning]
    require(len(final) == 3, 'closed final discriminator store')
    phi = re.fullmatch('(' + SSA + r') = phi i8 \[ 0, %' + re.escape(nonempty) + r' \], \[ 1, %' + re.escape(empty) + r' \]', final[0])
    require(phi is not None and final[1:] == [f'store i8 {phi[1]}, ptr %_0, align 8', 'ret void'],
            'nonempty ownership is success; empty rejection is error')
    require(set(graph) == {'start', empty, nonempty, returning}, 'all initialization blocks classified')
    return graph, (empty, nonempty, returning)


def cases(record):
    for row, _, core, assembly in comparison.cases(record):
        if row['profile'] == 'release':
            function, zero = select(core)
            # Reuse the existing bounded zero-store model and actual assembly
            # contract; no new interpreter or all-length claim.
            clearing.llvm.inspect(clearing.llvm.select(core))
            body = clearing.select(assembly)
            require(body.splitlines()[0] == zero + ':', 'matching emitted volatile-clearing symbol')
            clearing.inspect(body, row['target'].startswith('aarch64'))
            yield function, zero


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*case) for case in cases(record)]
    require(len(checks) == 8 and before == comparison.capture.sources(), 'complete unchanged optimized initialization matrix')
    print('Secret output begin: 8 optimized bodies, all 32 blocks; original-region clearing precedes ownership PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Initialization boundary only; not caller ordering, later write/drop behavior, abort or register/spill erasure; Arm remains QEMU')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
