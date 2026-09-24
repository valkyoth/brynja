#!/usr/bin/env python3
"""Retained accelerated producer entry/ownership transfer, not whole-call erasure."""
import argparse
import json
from pathlib import Path
import re
from types import SimpleNamespace

import check_kmac_accelerated_readers as readers
import check_secret_output_begin as beginning

adapter, comparison, require = readers.adapter, readers.comparison, readers.require
SSA = readers.SSA


def lifetime(line, kind, slot, width):
    name, args = adapter.routes.guard.call(line)
    require(name == 'llvm.lifetime.' + kind + '.p0' and args in
            (['ptr nonnull ' + slot], [f'i64 {width}', 'ptr nonnull ' + slot]), 'local lifetime boundary')


def copy(line, destination, source, destination_align, source_align):
    require(line == 'call void @llvm.memcpy.p0.p0.i64('
            f'ptr noundef nonnull align {destination_align} dereferenceable(23) {destination}, '
            f'ptr noundef nonnull align {source_align} dereferenceable(23) {source}, i64 23, i1 false)',
            'entire remaining 23 descriptor bytes, original addresses')


def inspect(function, begin, wipe, clear, arm):
    params = readers.arguments(function)
    require(function.startswith('define internal fastcc void @') and len(params) == 6
            and all(arg.endswith(' ' + value) for arg, value in zip(params,
                    ('%_0', '%self.0.val', '%output.0', '%output.1', '%0', '%1')))
            and 'dereferenceable(24)' in params[0] and params[4:] == ['i1 noundef zeroext %0', 'i8 %1'],
            'original accelerated producer arguments')
    graph, edges, _ = adapter.routes.transfer.finish.graph_info(function)
    branch = lambda label: adapter.shape.branch(SimpleNamespace(graph=graph), label)
    start = list(graph['start'])
    alignment = 4 if arm else 1
    allocations = {'%_5.i.i.i': (24, 8), '%initialization1.i.i.i': (24, 8),
                   '%_4.i': (32, 8), '%_10': (48, 8), '%_5.sroa.8': (23, alignment),
                   '%length': (8, 8), '%final_bits': (2, alignment)}
    if arm:
        allocations['%initialization.sroa.3'] = (23, 4)
    observed = {}
    while start and ' = alloca ' in start[0]:
        match = re.fullmatch('(' + SSA + r') = alloca \[(\d+) x i8\], align (\d+)', start.pop(0))
        require(match is not None and match[1] not in observed, 'distinct local metadata allocations')
        observed[match[1]] = (int(match[2]), int(match[3]))
    require(observed == allocations and len(start) == 9, 'closed pre-initialization local-only preparation')
    mode = readers.assigned(start[0], 'zext i1 %0 to i8')
    require(start[1] == f'store i8 {mode}, ptr %final_bits, align {alignment}', 'original final/bulk mode')
    valid = readers.assigned(start[2], 'getelementptr inbounds nuw i8, ptr %final_bits, i64 1')
    require(start[3] == f'store i8 %1, ptr {valid}, align 1', 'original final-bit count')
    lifetime(start[4], 'start', '%length', 8)
    require(start[5] == 'store i64 %output.1, ptr %length, align 8', 'original destination length')
    lifetime(start[6], 'start', '%_5.sroa.8', 23)
    empty_test = readers.assigned(start[7], 'icmp eq i64 %output.1, 0')
    tested, join, nonempty = branch('start')
    require(tested == empty_test and join != nonempty, 'only empty output skips initialization')

    block = graph[nonempty]
    require(len(block) == 5, 'closed initialization and discriminator decision')
    lifetime(block[0], 'start', '%_4.i', 32)
    name, args = adapter.routes.guard.call(block[1])
    require(block[1].startswith('call void @') and name == begin and len(args) == 3
            and 'sret([32 x i8])' in args[0] and args[0].endswith(' %_4.i')
            and comparison.pointer(args[1]) == '%output.0'
            and args[2].startswith('i64 ') and args[2].endswith(' %output.1'), 'actual initializer receives entire original destination')
    discriminator = readers.assigned(block[2], 'load i8, ptr %_4.i, align 8')
    failure = readers.assigned(block[3], 'trunc nuw i8 ' + re.escape(discriminator) + ' to i1')
    tested, rejected, success = branch(nonempty)
    require(tested == failure and len({join, rejected, success, nonempty, 'start'}) == 5, 'distinct initialization outcomes')

    block = graph[success]
    require(len(block) == 8, 'closed successful descriptor extraction')
    first = readers.assigned(block[0], 'getelementptr inbounds nuw i8, ptr %_4.i, i64 8')
    byte = readers.assigned(block[1], 'load i8, ptr ' + re.escape(first) + ', align 8')
    rest = readers.assigned(block[2], 'getelementptr inbounds nuw i8, ptr %_4.i, i64 9')
    copy(block[3], '%_5.sroa.8', rest, alignment, 1)
    lifetime(block[4], 'end', '%_4.i', 32)
    loaded_mode = readers.assigned(block[5], f'load i8, ptr %final_bits, align {alignment}')
    mode_bit = readers.assigned(block[6], 'trunc nuw i8 ' + re.escape(loaded_mode) + ' to i1')
    require(block[7] == 'br label %' + join, 'success reaches original common operation')

    block = graph[rejected]
    require(len(block) == 18, 'closed failed initialization cleanup and error')
    lifetime(block[0], 'end', '%_4.i', 32)
    nonnull = readers.assigned(block[1], 'icmp ne ptr %self.0.val, null')
    require(block[2] == f'tail call void @llvm.assume(i1 {nonnull})', 'original storage assumption')
    readers.clear_storage(block[3:13] + ['ret void'], '%self.0.val', wipe, clear)
    error_field = readers.assigned(block[13], 'getelementptr inbounds nuw i8, ptr %_0, i64 8')
    require(block[14:16] == [f'store i8 10, ptr {error_field}, align 8', 'store i64 2, ptr %_0, align 8'], 'SecretMemory error, never success')
    lifetime(block[16], 'end', '%_5.sroa.8', 23)
    require(len(edges[rejected][0]) == 1, 'one rejection return')
    returning = edges[rejected][0][0]
    require(block[-1] == 'br label %' + returning and len(graph[returning]) == 2 and graph[returning][-1] == 'ret void', 'rejection cannot enter producer work')
    lifetime(graph[returning][0], 'end', '%length', 8)

    block = list(graph[join])
    require(len(block) == (23 if arm else 22), 'closed ownership and metadata transfer')
    mode_phi = readers.assigned(block.pop(0), 'phi i1 \\[ ' + re.escape(mode_bit) + ', %' + re.escape(success) + r' \], \[ %0, %start \]')
    byte_phi = readers.assigned(block.pop(0), 'phi i8 \\[ ' + re.escape(byte) + ', %' + re.escape(success) + r' \], \[ undef, %start \]')
    present = readers.assigned(block.pop(0), 'phi i64 \\[ 1, %' + re.escape(success) + r' \], \[ 0, %start \]')
    if arm:
        copy(block.pop(0), '%initialization.sroa.3', '%_5.sroa.8', 4, 4)
        lifetime(block.pop(0), 'end', '%_5.sroa.8', 23)
        lifetime(block.pop(0), 'start', '%_10', 48)
    else:
        rest_destination = readers.assigned(block.pop(0), 'getelementptr inbounds nuw i8, ptr %_10, i64 9')
        lifetime(block.pop(0), 'start', '%_10', 48)
        copy(block.pop(0), rest_destination, '%_5.sroa.8', 1, 1)
        lifetime(block.pop(0), 'end', '%_5.sroa.8', 23)
    for offset, value in ((32, '%final_bits'), (40, '%length')):
        address = readers.assigned(block.pop(0), f'getelementptr inbounds nuw i8, ptr %_10, i64 {offset}')
        require(block.pop(0) == f'store ptr {value}, ptr {address}, align 8', 'original closure metadata reference')
    require(block.pop(0) == f'store i64 {present}, ptr %_10, align 8', 'owned initializer present only on success')
    first_destination = readers.assigned(block.pop(0), 'getelementptr inbounds nuw i8, ptr %_10, i64 8')
    require(block.pop(0) == f'store i8 {byte_phi}, ptr {first_destination}, align 8', 'first descriptor byte preserved')
    if arm:
        rest_destination = readers.assigned(block.pop(0), 'getelementptr inbounds nuw i8, ptr %_10, i64 9')
        copy(block.pop(0), rest_destination, '%initialization.sroa.3', 1, 4)
    require(len(block) == 8, 'closed remaining metadata-only entry')
    nonnull = readers.assigned(block[0], 'icmp ne ptr %self.0.val, null')
    require(block[1] == f'call void @llvm.assume(i1 {nonnull})'
            and all(re.fullmatch(r'call void @llvm.experimental.noalias.scope.decl\(metadata !\d+\)', line) for line in block[2:7]), 'no payload/owner reads before metadata dispatch')
    tested, final, bulk = branch(join)
    require(tested == mode_phi and final != bulk and not {final, bulk} & {'start', nonempty, success, rejected, join, returning}, 'original mode selects later producer work')
    require(len(graph[final]) == 6 and len(graph[bulk]) == 2, 'distinct final shape and bulk length entry')
    readers.assigned(graph[final][0], 'load i8, ptr ' + re.escape(valid) + ', align 1')
    readers.assigned(graph[bulk][0], 'load i64, ptr %length, align 8')
    return ('start', nonempty, success, rejected, join, returning)


def bind(case):
    # Same-row dependencies; do not pool equal names across targets/toolchains.
    begin, zero = beginning.select(case.core)
    beginning.inspect(begin, zero)
    core_clear = readers.chain.tail.ownership.wiping.core_check(case.core, case.assembly, case.compiler, case.arm)
    definitions = comparison.definitions(case.sha3)
    wipe = readers.staging.unique(definitions, 'accelerated', '6Memory4wipe')
    readers.memory_wipe(definitions[wipe], core_clear)
    producer = readers.staging.unique(definitions, 'accelerated', '8Borrowed6secret')
    return definitions[producer], readers.chain.symbol(begin), wipe, core_clear, case.arm


def cases(record):
    for case in readers.cases(record):
        yield bind(case)


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*case) for case in cases(record)]
    require(len(checks) == 8 and before == comparison.capture.sources(), 'complete unchanged optimized entry matrix')
    print('Accelerated producer initialization: eight instantiated paths PASS; entire destination initialized before producer checks')
    print('All 24 ownership descriptor bytes preserved; failure clears owned storage and returns SecretMemory')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Entry/transfer only; later producer completion, debug, register/spill and native Arm qualification remain separate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
