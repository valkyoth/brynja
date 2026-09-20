#!/usr/bin/env python3
"""Check retained KMAC candidate split/length routing, not whole-call erasure."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

import check_kmac_operand_routes as routes

require = routes.require
SSA = routes.SSA
LABEL = routes.guard.LABEL


def branch(trace, label):
    match = re.fullmatch(r'br i1 (' + SSA + r'), label %(' + LABEL + r'), label %(' + LABEL + ')', trace.graph[label][-1])
    require(match is not None, 'candidate-shape conditional branch')
    return match.groups()


def alignment_switch(trace, label, valid):
    lines = trace.graph[label]
    require(len(lines) >= 4, 'complete alignment switch')
    match = re.fullmatch(r'switch i8 ' + re.escape(valid) + r', label %(' + LABEL + r') \[', lines[-4])
    first = re.fullmatch(r'i8 0, label %(' + LABEL + ')', lines[-3])
    last = re.fullmatch(r'i8 8, label %(' + LABEL + ')', lines[-2])
    require(match is not None and first is not None and last is not None
            and lines[-1] == ']' and first[1] == last[1] and match[1] != first[1],
            'exact 0/8 aligned and non-aligned switch destinations')
    return first[1], match[1]


def unreachable(trace, start, forbidden, removed=None):
    pending, visited = [start], set()
    while pending:
        label = pending.pop()
        if label in visited:
            continue
        require(label not in forbidden, 'rejected shape or bypass must not reach verification work')
        visited.add(label)
        pending.extend(target for target in trace.edges[label][0] if (label, target) != removed)
    return visited


def inspect(function, names, defined, callees):
    trace = routes.inspect(function, names, defined, callees)
    prior = set(trace.used)
    readers = []
    for label, lines in trace.graph.items():
        for line in lines:
            if line.startswith('invoke void @'):
                name, args = routes.guard.call(line)
                if any(token in name for token in ('14squeeze_secret', '12final_secret', '25squeeze_final_bits_secret')):
                    readers.append((label, name, args))
    require(len(readers) == 2, 'unique bulk and final reader invocations')
    bulk = [entry for entry in readers if '14squeeze_secret' in entry[1]]
    tail = [entry for entry in readers if '14squeeze_secret' not in entry[1]]
    require(len(bulk) == len(tail) == 1, 'distinct bulk/final reader roles')
    bulk_label, _, args = bulk[0]
    width = re.search('(' + SSA + ')$', args[-1])
    require(width is not None, 'bulk reader byte-count SSA')
    remaining = trace.match(width[1], r'call noundef i64 @llvm.umin.i64\(i64 (' + SSA + r'), i64 64\)')[1]
    incoming = trace.phi(remaining, 'i64')
    initial = [(value, block) for value, block in incoming if trace.definitions.get(value, ('', ''))[1].startswith('phi i64 ')]
    require(len(initial) == 1, 'remaining count initialized from candidate split')
    split, preheader = initial[0]
    feedback, latch = next(entry for entry in incoming if entry != initial[0])
    trace.match(feedback, r'sub nuw(?: nsw)? i64 ' + re.escape(remaining) + ', ' + re.escape(width[1]))
    split_label = trace.definitions[split][0]
    text = trace.match(split, r'phi i64 (.+)')[1]
    entries = re.findall(r'\[ (' + SSA + r'), %(' + LABEL + r') \]', text)
    require(len(entries) == 3 and ', '.join(f'[ {v}, %{b} ]' for v, b in entries) == text,
            'three exact candidate split inputs')
    counts = Counter(entries)
    full = [entry for entry, count in counts.items() if count == 2]
    partial = [entry for entry, count in counts.items() if count == 1]
    require(len(full) == len(partial) == 1, 'two aligned inputs and one partial-byte input')
    length, alignment = full[0]
    decremented, subtraction = partial[0]
    trace.candidate(length, 'i64', 8)
    trace.match(decremented, r'add i64 ' + re.escape(length) + r', -1')
    require(trace.definitions[decremented][0] == subtraction, 'split decrement in partial-byte predecessor')
    tail_label, _, tail_args = tail[0]
    valid = re.fullmatch(r'i8 noundef (' + SSA + ')', tail_args[-1])
    require(valid is not None, 'final reader receives candidate valid-bit SSA')
    valid = valid[1]
    trace.candidate(valid, 'i8', 24)
    require(trace.definitions[valid][0] == alignment, 'alignment and final reader share candidate valid-bit field')
    require(alignment_switch(trace, alignment, valid) == (split_label, subtraction), 'split selected by candidate alignment')
    predecessors = Counter(source for source in trace.graph for target in trace.edges[source][0] if target == split_label)
    require(predecessors == Counter(block for _, block in entries), 'split phi accounts for every incoming edge')
    condition, error, success = branch(trace, subtraction)
    trace.match(condition, r'icmp eq i64 ' + re.escape(length) + ', 0')
    require(success == split_label and error != success, 'zero length rejects before using the decrement')
    work = {label for label, _, _ in trace.comparisons} | {bulk_label, tail_label}
    unreachable(trace, error, work)
    zero, after_bulk, enter = branch(trace, split_label)
    trace.match(zero, r'icmp eq i64 ' + re.escape(split) + ', 0')
    require(enter == preheader and after_bulk != enter and trace.graph[preheader][-1] == 'br label %' + bulk_label,
            'nonempty split enters the matching bulk reader loop')
    done, after_latch, again = branch(trace, latch)
    trace.match(done, r'icmp eq i64 ' + re.escape(feedback) + ', 0')
    require(after_latch == after_bulk and again == bulk_label, 'bulk exhaustion exits to the final-byte decision')
    aligned, partial_tail = alignment_switch(trace, after_bulk, valid)
    predicate = next(label for label, role, _ in trace.comparisons if role == 'PREDICATE')
    require(aligned == predicate, 'aligned candidates skip the final-byte reader')
    require(tail_label in unreachable(trace, partial_tail, set()), 'partial-byte edge actually reaches the final reader')
    unreachable(trace, 'start', {tail_label}, (after_bulk, partial_tail))
    trace.shape_values = trace.used - prior
    trace.shape_blocks = {alignment, subtraction, split_label, preheader, latch, after_bulk}
    return trace


def main(record):
    before = routes.comparison.capture.sources()
    count = values = blocks = 0
    for _, function, names, defined, callees in routes.cases(record):
        trace = inspect(function, names, defined, callees)
        count += 1
        values += len(trace.shape_values)
        blocks += len(trace.shape_blocks)
    require((count, values, blocks) == (24, 168, 144) and before == routes.comparison.capture.sources(), 'complete unchanged candidate-shape matrix')
    print(f'KMAC candidate shape: {count} verifiers, {values} additional SSA definitions and {blocks} selected blocks PASS')
    print('Record SHA-256: ' + routes.comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(routes.comparison.recorded.inspector_sources(), sort_keys=True))
    print('Checks split/length/valid-bit routing; not descriptor construction, callee masks/content, complete loop correctness or register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
