#!/usr/bin/env python3
"""Bind retained KMAC reader-result decisions to the compared output owners."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_compare_loop as loops

routes = loops.routes
shape = loops.shape
require = loops.require
SSA = loops.SSA


def output_slot(trace, actual):
    rhs = trace.definitions[actual][1]
    if rhs.startswith('getelementptr '):
        actual = trace.match(actual, r'getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 ' + SSA)[1]
    elif rhs.startswith('select '):
        actual = trace.match(actual, r'select i1 ' + SSA + r', ptr inttoptr \(i64 1 to ptr\), ptr (' + SSA + ')')[1]
    return trace.output(actual), actual


def before_next_reader(trace, start, forbidden, producer):
    pending, visited = [start], set()
    while pending:
        label = pending.pop()
        if label in visited or label == producer:
            continue
        require(label not in forbidden, 'rejected output owner cannot reach the current comparison')
        visited.add(label)
        pending.extend(trace.edges[label][0])


def inspect(function, names, defined, callees):
    trace = loops.inspect(function, names, defined, callees)
    previous = set(trace.used)
    trace.result_gates = []
    work = {label for label, _, _ in trace.comparisons}
    for label, lines in trace.graph.items():
        if any(line.startswith('invoke void @') and any(token in line for token in
               ('14squeeze_secret', '12final_secret', '25squeeze_final_bits_secret')) for line in lines):
            work.add(label)
    for comparison_label, role, args in trace.comparisons:
        if role != 'ACCUMULATE':
            continue
        slot, actual = output_slot(trace, routes.comparison.pointer(args[1]))
        stores = []
        for label, lines in trace.graph.items():
            for line in lines:
                match = re.fullmatch(r'store i64 (' + SSA + r'), ptr (' + SSA + r'), align 8', line)
                if match and trace.origin(match[2]) == (slot, 0):
                    stores.append((label, match[1], line))
        require(len(stores) == 1, 'unique compared-owner discriminator store')
        success, discriminator, store = stores[0]
        result = trace.match(discriminator, r'load i64, ptr (' + SSA + r'), align 8')[1]
        trace.match(result, r'alloca \[24 x i8\], align 8')
        decision = trace.definitions[discriminator][0]
        condition, error, accepted = shape.branch(trace, decision)
        require(accepted == success and error != success, 'reader success is the non-error branch')
        trace.match(condition, r'icmp eq i64 ' + re.escape(discriminator) + ', 2')
        require(trace.definitions[condition][0] == decision, 'reader discriminator tested where it is loaded')
        decision_lines = trace.graph[decision]
        require(decision_lines.index(discriminator + ' = ' + trace.definitions[discriminator][1])
                < decision_lines.index(condition + ' = ' + trace.definitions[condition][1]), 'load precedes result decision')
        # This small post-invoke decision block has no calls, writes, lifetimes
        # or hidden exits. Reader/copy internals are separate contracts.
        require(all(re.fullmatch(SSA + r' = (?:load|getelementptr|icmp) .+', line)
                    for line in decision_lines[:-1]), 'read-only result decision block')
        parents = [label for label in trace.graph if decision in trace.edges[label][0]]
        require(len(parents) == 1, 'one reader-result predecessor')
        producer = parents[0]
        invokes = [line for line in trace.graph[producer] if line.startswith('invoke void @')]
        require(len(invokes) == 1 and trace.edges[producer][0][0] == decision, 'decision follows reader normal return')
        name, produced_args = routes.guard.call(invokes[0])
        require(name in callees and any(token in name for token in
                ('14squeeze_secret', '12final_secret', '25squeeze_final_bits_secret'))
                and 'sret([24 x i8])' in produced_args[0] and produced_args[0].endswith(' ' + result),
                'decision reads this reader invocation result')
        require([label for label in trace.graph if success in trace.edges[label][0]] == [decision],
                'descriptor construction has no alternate predecessor')
        shape.unreachable(trace, error, work)
        shape.unreachable(trace, 'start', {comparison_label}, (decision, success))
        owned, present, absent = shape.branch(trace, success)
        trace.match(owned, r'trunc nuw i64 ' + re.escape(discriminator) + ' to i1')
        require(trace.definitions[owned][0] == success and present != absent,
                'payload ownership uses the transferred discriminator')
        require(trace.graph[success].index(store) < trace.graph[success].index(owned + ' = ' + trace.definitions[owned][1]),
                'owner discriminator is stored before interpretation')
        pointer_load = trace.definitions[actual][0]
        require(pointer_load == present, 'secret-output pointer is loaded only on the owned-payload edge')
        shape.unreachable(trace, 'start', {pointer_load}, (success, present))
        before_next_reader(trace, absent, {pointer_load, comparison_label}, producer)
        trace.result_gates.append((producer, decision, success, error, absent, comparison_label, store))
    require(len(trace.result_gates) == 2, 'both bulk and final output decisions checked')
    trace.result_values = trace.used - previous
    return trace


def main(record):
    before = routes.comparison.capture.sources()
    count = values = gates = 0
    for _, function, names, defined, callees in routes.cases(record):
        trace = inspect(function, names, defined, callees)
        count += 1
        values += len(trace.result_values)
        gates += len(trace.result_gates)
    require((count, gates, values) == (24, 48, 144) and before == routes.comparison.capture.sources(), 'complete unchanged reader-result matrix')
    print(f'KMAC reader results: {count} verifiers, {gates} result/ownership decisions and {values} additional SSA definitions PASS')
    print('Record SHA-256: ' + routes.comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(routes.comparison.recorded.inspector_sources(), sort_keys=True))
    print('Selected caller result/ownership routing; not callee result semantics, exact returned bytes/length, all alias effects or register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
