#!/usr/bin/env python3
"""Bound direct verifier memory accesses, not callee data flow or spill erasure."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_verify_comparisons as comparison

require = comparison.require
SSA = r'%[-.$\w]+'


def inspect(function):
    # These parameters are descriptors, not the key/message/tag byte buffers.
    # Core is at most 32 bytes (24 in the portable layout); bit-string
    # descriptors are 32 bytes. This is not a Rust object-layout safety proof.
    bounds = {'%self': 32, '%input': 32, '%candidate': 32}
    origins = {name: (name, 0) for name in bounds}
    definitions, geps = set(origins), []
    lines = [line.strip() for line in function.splitlines()[1:-1]
             if line.strip() and not line.strip().startswith((';', '#dbg_'))]
    for line in lines:
        definition = re.match('(' + SSA + r') = ', line)
        if definition:
            require(definition[1] not in definitions, 'unique verifier SSA definition')
            definitions.add(definition[1])
        allocation = re.fullmatch('(' + SSA + r') = alloca \[(\d+) x i8\], align \d+(?:, !dbg !\d+)?', line)
        if allocation:
            bounds[allocation[1]] = int(allocation[2])
            require(0 < bounds[allocation[1]] <= 64, 'reviewed descriptor/debug allocation size')
            origins[allocation[1]] = (allocation[1], 0)
        elif ' = alloca ' in line:
            raise ValueError('unreviewed local allocation')
        gep = re.fullmatch('(' + SSA + r') = getelementptr (?:inbounds )?(?:nuw )?i8, ptr (' + SSA
                           + r'), i64 (-?\d+)(?:, !dbg !\d+)?', line)
        if gep:
            geps.append(gep.groups())
    # Constant offsets from known frame/descriptor roots only. Loading a pointer
    # from a descriptor does NOT confer descriptor provenance on its pointee.
    for _ in range(len(geps) + 1):
        previous = len(origins)
        for destination, base, offset in geps:
            if base in origins:
                root, old = origins[base]
                origins[destination] = root, old + int(offset)
        if len(origins) == previous:
            break

    def bounded(address, width):
        require(address in origins, 'direct access through external/unresolved pointer: ' + address)
        root, offset = origins[address]
        require(width > 0 and 0 <= offset <= bounds[root] - width, 'direct access exceeds descriptor/frame bounds')

    def width(kind):
        require(kind == 'ptr' or int(kind[1:]) in (8, 16, 32, 64, 128), 'reviewed scalar memory width')
        return 8 if kind == 'ptr' else int(kind[1:]) // 8

    counts = [0, 0, 0]
    for line in lines:
        if re.search(r'\b(?:atomicrmw|cmpxchg|fence)\b|\basm\b', line):
            raise ValueError('unreviewed memory/assembly operation')
        if re.search(r'\bload\b', line):
            load = re.fullmatch(SSA + r' = load (i\d+|ptr), ptr (' + SSA
                                + r'), align \d+(?:, ![\w.]+ !\d+)*', line)
            require(load is not None, 'reviewed direct scalar load form')
            bounded(load[2], width(load[1]))
            counts[0] += 1
        if line.startswith('store '):
            store = re.fullmatch(r'store (i\d+|ptr) (?:' + SSA + r'|-?\d+|true|false|null), ptr ('
                                 + SSA + r'), align \d+(?:, ![\w.]+ !\d+)*', line)
            require(store is not None, 'reviewed direct scalar store form')
            bounded(store[2], width(store[1]))
            counts[1] += 1
        if re.search(r'@llvm\.(?:mem|masked|vp\.)', line):
            symbol = re.search(comparison.SYMBOL, line)
            require(symbol is not None and symbol[1] == 'llvm.memcpy.p0.p0.i64', 'reviewed memory intrinsic')
            args = comparison.arguments(line, symbol.end())
            require(len(args) == 4 and args[3] == 'i1 false', 'nonvolatile fixed-size copy')
            length = re.fullmatch(r'i64 (\d+)', args[2])
            require(length is not None, 'constant descriptor copy length')
            bounded(comparison.pointer(args[0]), int(length[1]))
            bounded(comparison.pointer(args[1]), int(length[1]))
            counts[2] += 1
    require(all(counts), 'nonvacuous verifier direct-memory inventory')
    return counts


def main(record):
    before = comparison.capture.sources()
    total, functions = [0, 0, 0], 0
    for row, kmac, _, _ in comparison.cases(record):
        for function in comparison.verifiers(kmac, row['mode'] == 'accelerated'):
            total = [a + b for a, b in zip(total, inspect(function))]
            functions += 1
    require(functions == 48 and total == [2152, 2288, 508], 'complete direct-memory inventory')
    require(before == comparison.capture.sources(), 'unchanged source closure')
    print('KMAC verifier direct memory: 48 bodies; 2152 loads, 2288 stores, 508 copies: PASS')
    print('All direct accesses stay in bounded stack/descriptor regions; loaded pointers are not trusted as descriptor roots')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not callee effects, complete pointer provenance, machine-code spills or erasure qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
