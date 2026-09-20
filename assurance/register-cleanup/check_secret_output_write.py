#!/usr/bin/env python3
"""Retained optimized initialization writes; no full squeeze/erasure claim."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_verify_comparisons as comparison
import check_secret_copy as copy_boundary

require = comparison.require
SSA = r'%[-.$\w]+'


def match(pattern, line):
    found = re.fullmatch(pattern, line)
    require(found is not None, 'unreviewed initialization-write instruction: ' + line)
    return found


def select(core):
    found = [body for name, body in comparison.definitions(core).items()
             if 'SecretRegionInitialization5write' in name]
    require(len(found) == 1, 'unique initialization write')
    return found[0]


def inspect(function, compiler):
    symbol = re.search(comparison.SYMBOL, function.splitlines()[0])
    params = comparison.arguments(function.splitlines()[0], symbol.end())
    require(len(params) == 3 and params[0].endswith(' %self')
            and params[1].endswith(' %input.0') and params[2].endswith(' %input.1')
            and re.search(r'\bi8\s*$', function.splitlines()[0][:symbol.start()]), 'initialization-write ABI')
    graph, label = {}, None
    for raw in function.splitlines()[1:-1]:
        line = raw.strip()
        if not line or line.startswith(';'):
            continue
        block = re.fullmatch(r'([\w.]+):(?:\s*;.*)?', line)
        if block:
            label = block[1]
            require(label not in graph, 'unique write block')
            graph[label] = []
        else:
            require(label is not None, 'write instruction in block')
            graph[label].append(re.sub(r'(?:, ![\w.]+ !\d+)+$', '', line))
    require(len(graph) == 5 and 'start' in graph, 'complete five-block write path')
    start = graph['start']
    require(len(start) == 3, 'presence-check block')
    region = match('(' + SSA + r') = load ptr, ptr %self, align 8', start[0])[1]
    absent = match('(' + SSA + r') = icmp eq ptr ' + re.escape(region) + ', null', start[1])[1]
    edges = match(r'br i1 ' + re.escape(absent) + r', label %(\S+), label %(\S+)', start[2])
    end_label, sum_label = edges[1], edges[2]
    require(sum_label in graph, 'overflow block exists')
    addition = graph[sum_label]
    require(len(addition) == 5, 'closed overflow-check block')
    position = match('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %self, i64 16', addition[0])[1]
    initialized = match('(' + SSA + r') = load i64, ptr ' + re.escape(position) + ', align 8', addition[1])[1]
    old = compiler == '1.90.0'
    require(old or compiler == '1.98.1', 'reviewed compiler identity')
    if old:
        aggregate = match('(' + SSA + r') = tail call \{ i64, i1 \} @llvm.uadd.with.overflow.i64\(i64 '
                          + re.escape(initialized) + r', i64 %input.1\)', addition[2])[1]
        overflow = match('(' + SSA + r') = extractvalue \{ i64, i1 \} ' + re.escape(aggregate) + ', 1', addition[3])[1]
        end = None
    else:
        end = match('(' + SSA + r') = add i64 ' + re.escape(initialized) + r', %input.1', addition[2])[1]
        overflow = match('(' + SSA + r') = icmp ult i64 ' + re.escape(end) + ', ' + re.escape(initialized), addition[3])[1]
    edges = match(r'br i1 ' + re.escape(overflow) + r', label %' + re.escape(end_label) + r', label %(\S+)', addition[4])
    capacity_label = edges[1]
    require(capacity_label in graph, 'capacity block exists')
    capacity = graph[capacity_label]
    require(len(capacity) == (5 if old else 4), 'closed capacity-check block')
    length_ptr = match('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %self, i64 8', capacity[0])[1]
    length = match('(' + SSA + r') = load i64, ptr ' + re.escape(length_ptr) + ', align 8', capacity[1])[1]
    if old:
        end = match('(' + SSA + r') = add nuw i64 ' + re.escape(initialized) + r', %input.1', capacity[2])[1]
    too_long = match('(' + SSA + r') = icmp ugt i64 ' + re.escape(end) + ', ' + re.escape(length), capacity[-2])[1]
    copy_label = match(r'br i1 ' + re.escape(too_long) + ', label %' + re.escape(end_label) + r', label %(\S+)', capacity[-1])[1]
    require(copy_label in graph, 'copy block exists')
    copying = graph[copy_label]
    require(len(copying) == 4, 'exact copy then progress-commit block')
    destination = match('(' + SSA + r') = getelementptr inbounds nuw i8, ptr ' + re.escape(region) + ', i64 ' + re.escape(initialized), copying[0])[1]
    callee = re.search(comparison.SYMBOL, copying[1])
    require(callee is not None and 'secret_memory_transfer10copy_bytes' in callee[1]
            and copying[1][:callee.start()] == 'tail call fastcc void ', 'reviewed secret-copy boundary')
    args = comparison.arguments(copying[1], callee.end())
    require(len(args) == 3 and comparison.pointer(args[0]) == destination
            and comparison.pointer(args[1]) == '%input.0', 'exact source/destination forwarding')
    match(r'i64 (?:noundef )?(?:range\(i64 0, -9223372036854775808\) )?%input.1', args[2])
    require(re.fullmatch(r'(?: #\d+)?', copying[1][copying[1].rfind(')') + 1:]), 'plain secret-copy call suffix')
    match('store i64 ' + re.escape(end) + ', ptr ' + re.escape(position) + ', align 8', copying[2])
    match('br label %' + re.escape(end_label), copying[3])
    require(end_label in graph, 'write result block exists')
    result = graph[end_label]
    require(len(result) == 2, 'closed value-free write result')
    phi = match('(' + SSA + r') = phi i8 (.+)', result[0])
    entries = re.findall(r'\[ (-?\d+), %(\S+) \]', phi[2])
    require(len(entries) == 4 and len({label for _, label in entries}) == 4
            and ', '.join(f'[ {value}, %{label} ]' for value, label in entries) == phi[2], 'exact write result predecessors')
    expected = {'start': 3, sum_label: 1, capacity_label: 2, copy_label: 4 if old else -1}
    require({label: int(value) for value, label in entries} == expected, 'correct error and success discriminants')
    match('ret i8 ' + re.escape(phi[1]), result[1])
    require(set(graph) == {'start', sum_label, capacity_label, copy_label, end_label}
            and len(expected) == 4, 'all write blocks inspected')


def cases(record):
    for row, _, core, assembly in comparison.cases(record):
        if row['profile'] == 'release':
            yield select(core), row['compiler'].splitlines()[0].split()[1], assembly, row['target'].startswith('aarch64')


def main(record):
    before = comparison.capture.sources()
    count = 0
    for function, compiler, assembly, arm in cases(record):
        inspect(function, compiler)
        copy_boundary.inspect(assembly, arm)
        count += 1
    require(count == 8 and before == comparison.capture.sources(), 'complete unchanged write matrix')
    print('Secret output write: eight optimized bodies, 40 blocks and eight copy assembly boundaries PASS')
    print('Presence, overflow and capacity checks precede exact copy; progress commits only afterward')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not source-byte generation correctness, debug code, all spills or native-platform qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
