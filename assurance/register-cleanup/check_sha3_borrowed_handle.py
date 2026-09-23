#!/usr/bin/env python3
"""Retained portable borrowed-reader handle non-escape and field preservation."""
import argparse
import json
from pathlib import Path
import re

import check_sha3_final_reader as reader

comparison = reader.comparison
require = reader.require
SSA = reader.SSA


def inspect(function):
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    require(symbol is not None and header.startswith('define internal fastcc void @'), 'borrowed secret definition ABI')
    args = comparison.arguments(header, symbol.end())
    require(len(args) == 6 and args[1].startswith('ptr noalias ') and 'dereferenceable(16)' in args[1],
            'exclusive bounded borrowed handle parameter')
    handle = comparison.pointer(args[1])
    graph, _, _ = reader.adapter.routes.transfer.finish.graph_info(function)
    lines = [(label, index, line) for label, block in graph.items() for index, line in enumerate(block)]
    # Follow only literal byte addressing. Any other use of an address in this
    # closure rejects below, including phi/select, integer casts and escapes.
    addresses = {handle: 0}
    changed = True
    while changed:
        changed = False
        for _, _, line in lines:
            gep = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (-?\d+)', line)
            if gep and gep[2] in addresses and gep[1] not in addresses:
                offset = addresses[gep[2]] + int(gep[3])
                require(offset in (0, 8), 'only owner/lifecycle field addresses')
                addresses[gep[1]] = offset
                changed = True
    owner_loads, flag_loads, flag_stores, uses = [], [], [], []
    for label, index, line in lines:
        used = set(re.findall(SSA, line)) & addresses.keys()
        if not used:
            continue
        uses.append((label, index, line))
        gep = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (-?\d+)', line)
        if gep:
            require(used == {gep[1], gep[2]} and gep[1] in addresses and gep[2] in addresses,
                    'closed constant handle addressing')
            continue
        load = re.fullmatch('(' + SSA + r') = load (ptr|i8), ptr (' + SSA + r'), align 8', line)
        if load:
            require(used == {load[3]} and load[1] not in addresses
                    and (load[2], addresses[load[3]]) in (('ptr', 0), ('i8', 8)),
                    'read only correctly typed owner/lifecycle fields')
            (owner_loads if load[2] == 'ptr' else flag_loads).append((label, index, load[1]))
            continue
        store = re.fullmatch(r'store i8 (0|1), ptr (' + SSA + r'), align 8', line)
        require(store is not None and used == {store[2]} and addresses[store[2]] == 8,
                'handle never escapes or changes owner pointer; only lifecycle byte stores permitted: ' + line)
        flag_stores.append((label, index, int(store[1])))
    require(len(owner_loads) == 2 and len(flag_loads) == 1 and sorted(value for _, _, value in flag_stores) == [0, 0, 1],
            'complete observed owner/lifecycle use inventory')
    return graph, uses, addresses


def cases(record):
    for function, definitions, wipes in reader.cases(record):
        _, _, secret = reader.inspect(function, definitions, wipes)
        yield definitions[secret]


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(function) for function in cases(record)]
    require(len(checks) == 16 and before == comparison.capture.sources(), 'complete unchanged borrowed handle matrix')
    blocks = sum(len(graph) for graph, _, _ in checks)
    uses = sum(len(uses) for _, uses, _ in checks)
    require((blocks, uses) == (504, 128), 'complete retained handle-use inventory')
    print(f'Portable borrowed handle: 16 bodies, all {blocks} blocks scanned, {uses} field/address uses PASS')
    print('Owner-pointer bytes are neither written nor passed/escaped; lifecycle writes stay at byte 8')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Local handle preservation under valid exclusive-reference contracts; not wipe/squeeze semantics, external aliases, spills or register erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
