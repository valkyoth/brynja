#!/usr/bin/env python3
"""Retained optimized KMAC bulk-comparison loop geometry under reader contracts."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_candidate_shape as shape

routes = shape.routes
require = shape.require
SSA = shape.SSA


def inspect(function, names, defined, callees):
    trace = shape.inspect(function, names, defined, callees)
    prior = set(trace.used)
    bulk = []
    for label, role, args in trace.comparisons:
        if role == 'ACCUMULATE':
            actual = routes.comparison.pointer(args[1])
            if trace.definitions[actual][1].startswith('getelementptr '):
                bulk.append((label, actual))
    require(len(bulk) == 1, 'unique indexed comparison')
    call_label, actual = bulk[0]
    pointer, index = trace.match(actual, r'getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (' + SSA + ')').groups()
    slot = trace.output(pointer)
    entries = trace.phi(index, 'i64')
    initial = [entry for entry in entries if entry[0] == '0']
    require(len(initial) == 1, 'zero-based comparison loop')
    preheader = initial[0][1]
    increment, latch = next(entry for entry in entries if entry[0] != '0')
    trace.match(increment, r'add nuw nsw i64 ' + re.escape(index) + r', 1')
    header = trace.definitions[index][0]
    done, exit_label, repeat = shape.branch(trace, latch)
    limit = trace.match(done, r'icmp eq i64 ' + re.escape(increment) + ', (' + SSA + ')')[1]
    require(repeat == header and exit_label != header, 'next byte repeats until the paired length is exhausted')
    width, length = trace.match(limit,
        r'call(?: noundef)? i64 @llvm.umin.i64\(i64(?: range\(i64 0, (?:65|169)\))? (' + SSA + '), i64 (' + SSA + r')\)').groups()
    trace.match(width, r'call noundef i64 @llvm.umin.i64\(i64 ' + SSA + r', i64 64\)')
    length_field = trace.match(length, r'load i64, ptr (' + SSA + r'), align 8')[1]
    require(trace.origin(length_field) == (slot, 16), 'comparison length belongs to the actual secret-output descriptor')
    trace.match(length_field, r'getelementptr inbounds nuw i8, ptr ' + re.escape(slot) + ', i64 16')
    producer = routes.output_producer(trace, slot, trace.owner, width, False, callees)
    # Check the actual loop-entry branch, not just the presence of a null/zero
    # comparison elsewhere. LLVM 20 combines the guards; LLVM 22 separates them.
    guarded = set()
    if trace.graph[preheader][-1] == 'br label %' + header:
        parents = [label for label in trace.graph if preheader in trace.edges[label][0]]
        require(len(parents) == 1, 'single comparison-loop preheader guard')
        guard_label = parents[0]
        condition, rejected, admitted = shape.branch(trace, guard_label)
        null, zero = trace.match(condition, r'select i1 (' + SSA + r'), i1 true, i1 (' + SSA + ')').groups()
        require(admitted == preheader and rejected != admitted, 'combined null/empty guard rejects')
        guarded.update((guard_label, preheader))
    else:
        zero, rejected, admitted = shape.branch(trace, preheader)
        require(admitted == header and rejected != header, 'empty secret output skips comparison')
        parents = [label for label in trace.graph if preheader in trace.edges[label][0]]
        require(len(parents) == 1, 'single null-pointer guard before length test')
        guard_label = parents[0]
        null, null_rejected, nonnull = shape.branch(trace, guard_label)
        require(nonnull == preheader and null_rejected == rejected, 'null and empty outputs share rejection')
        guarded.update((guard_label, preheader))
    trace.match(null, r'icmp eq ptr ' + re.escape(pointer) + ', null')
    trace.match(zero, r'icmp eq i64 ' + re.escape(length) + ', 0')
    require(trace.definitions[null][0] == guard_label and trace.definitions[zero][0] in guarded,
            'null/empty tests executed at the reviewed entry guards')
    # Per-iteration guard dominance: stopping at the outer reader prevents the
    # next chunk from being mistaken for an entry into this same iteration.
    shape.unreachable(trace, 'start', {header}, (guard_label, preheader))
    pending, seen = [rejected], set()
    while pending:
        label = pending.pop()
        if label == producer or label in seen:
            continue
        require(label not in (header, call_label), 'rejected output cannot enter the same comparison iteration')
        seen.add(label)
        pending.extend(trace.edges[label][0])
    if header == call_label:
        require(trace.edges[call_label][0][0] == latch and trace.definitions[increment][0] == latch,
                'direct accumulation advances its loop on normal return')
    else:
        # LLVM 20 retains the one-byte difference loop already checked by
        # routes.difference(). Its completed edge must enter this byte latch.
        inner = trace.graph[header][-1]
        match = re.fullmatch(r'br label %(' + shape.LABEL + ')', inner)
        require(match is not None, 'comparison byte enters the difference loop')
        inner_header = match[1]
        _, completed, body = shape.branch(trace, inner_header)
        require(completed == latch and body == call_label and trace.definitions[increment][0] == header,
                'completed difference byte advances the outer byte loop')
    trace.loop_values = trace.used - prior
    trace.loop_blocks = guarded | {header, latch}
    return trace


def main(record):
    before = routes.comparison.capture.sources()
    functions = values = blocks = 0
    for _, function, names, defined, callees in routes.cases(record):
        trace = inspect(function, names, defined, callees)
        functions += 1
        values += len(trace.loop_values)
        blocks += len(trace.loop_blocks)
    require((functions, values, blocks) == (24, 156, 96) and before == routes.comparison.capture.sources(), 'complete unchanged comparison-loop matrix')
    print(f'KMAC comparison loop: {functions} verifiers, {values} additional SSA definitions and {blocks} selected blocks PASS')
    print('Record SHA-256: ' + routes.comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(routes.comparison.recorded.inspector_sources(), sort_keys=True))
    print('Selected loop geometry only; exact returned length/content remains a reader contract, not whole-call/register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
