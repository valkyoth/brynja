#!/usr/bin/env python3
"""Retained initialization-handle transfer and terminal-reader destination drop."""
import argparse
import json
from pathlib import Path
import re

import check_sha3_reader_initialization as entry
import check_secret_output_drop as destructor

adapter = entry.adapter
comparison = entry.comparison
require = entry.require
SSA = entry.SSA


def inspect(function, begin, wipes, drop):
    trace, (nonempty, _, accepted, returning), _, _ = entry.inspect(function, begin, wipes)
    graph = trace.graph
    _, _, origin = adapter.routes.transfer.finish.graph_info(function)
    empty_condition, merge, _ = adapter.shape.branch(trace, 'start')
    _, params = adapter.routes.guard.call(graph[nonempty][1])
    result = re.search('(' + SSA + ')$', params[0])[1]
    allocations = {m[1]: int(m[2]) for line in graph['start']
                   if (m := re.fullmatch('(' + SSA + r') = alloca \[(\d+) x i8\], align (1|4|8)', line))}

    def assigned(line, pattern, label):
        match = re.fullmatch('(' + SSA + ') = ' + pattern, line)
        require(match is not None, label)
        return match[1]

    def gep(line, base, offset):
        return assigned(line, r'getelementptr inbounds nuw i8, ptr ' + re.escape(base) + ', i64 ' + str(offset), 'original descriptor field address')

    def lifetime(line, kind, slot, width):
        name, args = adapter.routes.guard.call(line)
        require(name == 'llvm.lifetime.' + kind + '.p0' and args in
                (['ptr nonnull ' + slot], [f'i64 {width}', 'ptr nonnull ' + slot]), 'whole local descriptor lifetime')

    def copy(line, destination, source):
        name, args = adapter.routes.guard.call(line)
        require(line.startswith('call void @') and name == 'llvm.memcpy.p0.p0.i64' and len(args) == 4
                and comparison.pointer(args[0]) == destination and comparison.pointer(args[1]) == source
                and args[2:] == ['i64 23', 'i1 false'], 'complete unchanged 23-byte descriptor tail')

    # A one-byte load plus an opaque 23-byte copy preserves the entire 24-byte
    # initialization descriptor. Padding is copied, not claimed initialized.
    first = graph[accepted]
    require(len(first) == 6, 'closed initializer success transfer')
    head = gep(first[0], result, 8)
    byte = assigned(first[1], r'load i8, ptr ' + re.escape(head) + ', align 8', 'first byte of original initialization descriptor')
    tail = gep(first[2], result, 9)
    _, args = adapter.routes.guard.call(first[3])
    require(len(args) == 4, 'complete staging copy arguments')
    staging = comparison.pointer(args[0])
    require(allocations.get(staging) == 23 and staging != result, 'distinct bounded tail staging')
    copy(first[3], staging, tail)
    lifetime(first[4], 'end', result, 32)
    require(first[5] == 'br label %' + merge, 'transfer reaches shared lifecycle decision')
    require([label for label in graph if accepted in trace.edges[label][0]] == [nonempty], 'successful initialization alone supplies descriptor')
    require(set(label for label in graph if merge in trace.edges[label][0]) == {'start', accepted}, 'only empty or initialized region enters lifecycle decision')

    merged = [line for line in graph[merge] if not re.fullmatch(
        r'call void @llvm.experimental.noalias.scope.decl\(metadata !\d+\)', line)]
    require(len(merged) == 16, 'closed descriptor reconstruction and lifecycle decision')
    first_byte = assigned(merged[0], r'phi i8 \[ ' + re.escape(byte) + ', %' + re.escape(accepted) + r' \], \[ undef, %start \]', 'original descriptor byte or absent-region padding')
    present = assigned(merged[1], r'phi i64 \[ 1, %' + re.escape(accepted) + r' \], \[ 0, %start \]', 'ownership present exactly after initialization')
    name, args = adapter.routes.guard.call(merged[2])
    local = comparison.pointer(args[-1])
    require(allocations.get(local) == 48 and local not in (result, staging), 'distinct complete operation descriptor')
    lifetime(merged[2], 'start', local, 48)
    require(merged[3] == f'store i64 {present}, ptr {local}, align 8', 'preserved ownership discriminator')
    output = gep(merged[4], local, 8)
    require(merged[5] == f'store i8 {first_byte}, ptr {output}, align 8', 'original initialization first byte')
    output_tail = gep(merged[6], local, 9)
    copy(merged[7], output_tail, staging)
    for index, offset, original, width in ((8, 32, '%valid', 2), (10, 40, '%length', 8)):
        field = gep(merged[index], local, offset)
        require(allocations.get(original) == width and merged[index + 1] == f'store ptr {original}, ptr {field}, align 8', 'separate bounded public operation metadata')
    active_field = gep(merged[12], '%self', 8)
    active = assigned(merged[13], r'load i8, ptr ' + re.escape(active_field) + ', align 8', 'actual reader lifecycle byte')
    tested = assigned(merged[14], r'trunc nuw i8 ' + re.escape(active) + ' to i1', 'reader lifecycle decision')
    condition, live, terminal = adapter.shape.branch(trace, merge)
    require(condition == tested and live != terminal, 'inactive reader takes terminal error path')

    rejected = graph[terminal]
    require(len(rejected) == 4, 'closed terminal reader rejection')
    error_field = gep(rejected[0], '%_0', 8)
    require(rejected[1:3] == [f'store i8 0, ptr {error_field}, align 8', 'store i64 2, ptr %_0, align 8'], 'value-free StateConsumed error')
    condition, done, dropping = adapter.shape.branch(trace, terminal)
    require(condition == empty_condition and done != dropping, 'only original empty destination bypasses Drop')
    cleanup = graph[dropping]
    require(len(cleanup) == 2 and cleanup[0].startswith('call void @'), 'one terminal destination destructor')
    name, args = adapter.routes.guard.call(cleanup[0])
    require(name == drop and len(args) == 1 and comparison.pointer(args[0]) == output
            and origin(output) == (local, 8), 'verified destructor receives complete original initialization descriptor')
    require(cleanup[1] == 'br label %' + done, 'cleanup completes before returning terminal error')
    require(len(graph[done]) == 2 and graph[done][1] == 'br label %' + returning, 'no work after terminal destination cleanup')
    lifetime(graph[done][0], 'end', local, 48)
    return trace, (accepted, merge, terminal, dropping, done), (result, staging, local)


def cases(record):
    drops = set()
    for function, zero in destructor.cases(record):
        destructor.inspect(function, zero)
        drops.add(re.search(comparison.SYMBOL, function.splitlines()[0])[1])
    for function, begin, wipes in entry.cases(record):
        called = {adapter.routes.guard.call(line)[0]
                  for lines in adapter.routes.guard.metadata.model.blocks(function).values() for line in lines
                  if (line.startswith('call void @') or line.startswith('invoke void @'))
                  and 'SecretRegionInitialization' in line and '4drop' in line}
        require(len(called) == 1 and called <= drops, 'reader-bound verified initialization destructor')
        yield function, begin, wipes, called.pop()


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*case) for case in cases(record)]
    require(len(checks) == 16 and before == comparison.capture.sources(), 'complete unchanged terminal output matrix')
    print('Terminal reader output: 16 complete initialization transfers; nonempty rejected destinations reach verified Drop PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Terminal-state path only; not active squeezing, recoverable-unwind coverage, padding initialization or register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
