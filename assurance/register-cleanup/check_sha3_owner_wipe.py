#!/usr/bin/env python3
"""Bind retained final-reader owner wipes to complete owned-region clearing."""
import argparse
import json
from pathlib import Path
import re

import check_sha3_final_reader as reader
import check_kmac_metadata_clear as bridge
import check_volatile_clear_assembly as clearing

comparison = reader.comparison
require = reader.require
SSA = reader.SSA
# Retained compiler layout, reviewed against HardenedFips202Owner's thirteen
# byte-array fields. This is not a stable Rust layout or a register/spill claim.
REGIONS = ((48, 200), (248, 168), (0, 16), (16, 16), (32, 16),
           (1036, 1), (1037, 3), (1032, 4), (416, 168), (584, 168),
           (752, 40), (792, 40), (832, 200))


def inspect(function, clear):
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    require(symbol is not None and header.startswith('define void @')
            and 'HardenedFips202Owner' in symbol[1] and '4wipe' in symbol[1], 'defined owner wipe')
    args = comparison.arguments(header, symbol.end())
    require(len(args) == 1 and 'noalias' in args[0] and 'dereferenceable(1040)' in args[0], 'exclusive complete owner ABI')
    owner = comparison.pointer(args[0])
    graph, _, origin = reader.adapter.routes.transfer.finish.graph_info(function)
    require(set(graph) == {'start'} and graph['start'][-1] == 'ret void', 'straight-line complete wipe')
    regions = []
    for line in graph['start'][:-1]:
        gep = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (\d+)', line)
        if gep:
            base, offset = origin(gep[1])
            require(base == owner and 0 <= offset < 1040, 'original owner field addressing')
            continue
        require(re.match(SSA + r' = tail call noundef i8 @', line) is not None, 'only bound clearing requests in owner wipe')
        name, params = reader.adapter.routes.guard.call(line)
        width = re.fullmatch(r'i64 noundef (\d+)', params[1]) if len(params) == 2 else None
        require(name == clear and width is not None, 'actual core clearing function and literal field width')
        base, offset = origin(comparison.pointer(params[0]))
        width = int(width[1])
        require(base == owner and width > 0 and 0 <= offset <= 1040 - width, 'bounded region in original owner')
        regions.append((offset, width))
    require(tuple(regions) == REGIONS, 'all thirteen original fields cleared in reviewed order')
    covered = [byte for offset, width in regions for byte in range(offset, offset + width)]
    require(len(covered) == 1040 and sorted(covered) == list(range(1040)), 'complete disjoint 1040-byte storage coverage')
    return regions


def core_check(core, assembly, compiler, arm):
    definitions = comparison.definitions(core)
    names, functions = {}, {}
    for role, token in (('CLEAR', '18clear_owned_region'), ('ZERO', 'secret_memory_volatile23zeroize_region_volatile')):
        names[role], functions[role] = bridge.one(definitions, lambda name: token in name, role)
    bridge.bridge(functions, names, compiler, 'release')
    zero = clearing.llvm.select(core)
    graph = clearing.llvm.shared.graph(zero)
    covered = set()
    for width in sorted({width for _, width in REGIONS}):
        covered.update(clearing.llvm.execute(graph, width, 17))
    require(covered == set(graph), 'every volatile-clear block reached by actual owner region widths')
    body = clearing.select(assembly)
    require(body.splitlines()[0] == names['ZERO'] + ':', 'assembly belongs to this exact core volatile callee')
    clearing.inspect(body, arm)
    return names['CLEAR']


def cases(record):
    for row, caller, callees in reader.adapter.cases(record):
        def artifact(package, suffix):
            paths = [record.parent / path for path in row['artifacts']
                     if Path(path).name.startswith(package + '-') and path.endswith(suffix)]
            require(len(paths) == 1, 'unique validated wipe dependency artifact')
            return paths[0].read_text()
        sha3 = artifact('brynja_hash_sha3', '.ll')
        definitions = comparison.definitions(sha3)
        trace = reader.adapter.inspect(caller, callees)
        label, index, *_ = trace.adapter_details
        name, _ = reader.adapter.routes.guard.call(trace.graph[label][index])

        def resolve(name, signature):
            if name not in definitions:
                aliases = re.findall(r'^@' + re.escape(name) + r' = unnamed_addr alias ' + re.escape(signature) + r', ptr @([^\n]+)$', sha3, re.M)
                require(len(aliases) == 1 and aliases[0] in definitions, 'unique bound alias to a defined body')
                name = aliases[0]
            return definitions[name]

        final = resolve(name, 'void (ptr, ptr, i1, ptr)')
        graph, labels, _ = reader.inspect(final, definitions, reader.adapter.routes.early.state_symbols(sha3))
        wipe, _ = reader.adapter.routes.guard.call(graph[labels[0]][1])
        yield resolve(wipe, 'void (ptr)'), artifact('brynja_core', '.ll'), artifact('brynja_core', '.s'), row['compiler'].splitlines()[0].split()[1], row['target'].startswith('aarch64')


def main(record):
    before = comparison.capture.sources()
    count = 0
    for function, core, assembly, compiler, arm in cases(record):
        inspect(function, core_check(core, assembly, compiler, arm))
        count += 1
    require(count == 16 and before == comparison.capture.sources(), 'complete unchanged bound wipe matrix')
    print('SHA-3 owner wipe: 16 reader-bound checks, 13 disjoint regions covering all 1040 owner bytes each PASS')
    print('Core forwarding, seven actual region widths and matching volatile-clear assembly checked')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Owned-memory normal completion only; not asynchronous/abort cleanup, whole-call spills or register erasure; Arm remains QEMU')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
