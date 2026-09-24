#!/usr/bin/env python3
"""Retained bulk squeeze loop progress and successful counter-commit routing."""
import argparse
import json
from pathlib import Path
import re
from types import SimpleNamespace

import check_sha3_squeeze_ownership as ownership

adapter = ownership.adapter
comparison = ownership.comparison
require = ownership.require
SSA = ownership.SSA
LABEL = r'(?:"[^"]+"|[-.$\w]+)'


def assignment(line, pattern, label):
    match = re.fullmatch('(' + SSA + ') = ' + pattern, line)
    require(match is not None, label)
    return match[1]


def inspect(function, write, clear, bulk, compiler, fill):
    graph, _, (writing, _, _, returning), final = ownership.inspect(function, write, clear, bulk, compiler)
    require(not final, 'bulk squeeze loop only')
    _, edges, _ = adapter.routes.transfer.finish.graph_info(function)
    trace = SimpleNamespace(graph=graph, edges=edges)
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    args = comparison.arguments(header, symbol.end())
    owner = comparison.pointer(args[0])
    requested = re.fullmatch('i64 noundef (' + SSA + ')', args[2])
    require(requested is not None, 'original requested byte count')
    requested = requested[1]
    _, rejected, preheader = adapter.shape.branch(trace, 'start')
    require(rejected == returning, 'overflow rejection bypasses all loop work')
    lines = graph[preheader]
    require(len(lines) == 2, 'closed zero-length decision')
    zero = assignment(lines[0], 'icmp eq i64 ' + re.escape(requested) + ', 0', 'test original zero request')
    tested, commit, setup = adapter.shape.branch(trace, preheader)
    require(tested == zero and commit != setup, 'only nonzero requests enter bulk loop')
    lines = graph[setup]
    require(len(lines) == 2 and len(edges[setup][0]) == 1, 'one bounded loop setup')
    staging = assignment(lines[0], 'getelementptr inbounds nuw i8, ptr ' + re.escape(owner) + ', i64 584', 'original staging address')
    head = edges[setup][0][0]
    require(lines[1] == 'br label %' + head, 'setup enters loop directly')
    _, progress, write_error = adapter.shape.branch(trace, writing)
    require(write_error == returning, 'write rejection bypasses progress and counter commit')
    lines = graph[head]
    require(len(lines) == 5, 'closed fill-stage iteration')
    phi = re.fullmatch('(' + SSA + r') = phi i64 \[ ' + re.escape(requested) + ', %' + re.escape(setup)
                       + r' \], \[ (' + SSA + '), %' + re.escape(progress) + r' \]', lines[0])
    require(phi is not None, 'remaining count starts at request and uses exact prior progress')
    remaining, next_remaining = phi[1], phi[2]
    chunk = re.fullmatch('(' + SSA + r') = tail call noundef i64 @llvm.umin.i64\(i64 '
                         + re.escape(remaining) + r', i64 (136|168)\)', lines[1])
    require(chunk is not None, 'chunk is min of remaining and supported rate')
    count, rate = chunk[1], int(chunk[2])
    result = re.match('(' + SSA + r') = tail call fastcc noundef i8 @', lines[2])
    name, params = adapter.routes.guard.call(lines[2])
    require(result is not None and name == fill and len(params) == 2
            and comparison.pointer(params[0]) == owner and params[1] == 'i64 noundef ' + count,
            'actual fill callee receives original owner and current bounded chunk')
    success = '5' if compiler == '1.90.0' else '-1'
    condition = assignment(lines[3], 'icmp eq i8 ' + re.escape(result[1]) + ', ' + success, 'fill success decision')
    tested, filled, fill_error = adapter.shape.branch(trace, head)
    require(tested == condition and filled == writing and fill_error == returning, 'only successful fill reaches write')
    _, params = adapter.routes.guard.call(graph[writing][0])
    require(comparison.pointer(params[1]) == staging and params[2] == 'i64 noundef ' + count,
            'write uses the exact freshly staged chunk')
    lines = graph[progress]
    require(len(lines) == 3 and lines[0] == f'{next_remaining} = sub nuw i64 {remaining}, {count}',
            'successful write advances by exactly the current chunk')
    condition = assignment(lines[1], 'icmp ugt i64 ' + re.escape(remaining) + ', ' + str(rate), 'repeat iff bytes remain after chunk')
    tested, repeat, done = adapter.shape.branch(trace, progress)
    require(tested == condition and repeat == head and done == commit, 'repeat nonempty remainder or commit on exact exhaustion')
    returned = graph[returning]
    phi_result = re.fullmatch('(' + SSA + r') = phi i8 (.+)', returned[0])
    require(phi_result is not None and len(returned) == 2 and returned[1] == 'ret i8 ' + phi_result[1], 'one value-only bulk return')
    entries = re.findall(r'\[ (' + SSA + r'|-?\d+), %(' + LABEL + r') \]', phi_result[2])
    require(len(entries) == 4 and ', '.join(f'[ {value}, %{parent} ]' for value, parent in entries) == phi_result[2]
            and dict((parent, value) for value, parent in entries) == {'start': '2', commit: success, head: result[1], writing: '4'},
            'overflow/write/fill errors preserved; only completed loop returns success')
    require(len(edges[commit][0]) == 1 and graph[commit][-1] == 'br label %' + returning,
            'counter commit has one normal success exit')
    predecessors = {preheader: {'start'}, setup: {preheader}, head: {setup, progress}, writing: {head},
                    progress: {writing}, commit: {preheader, progress}, returning: {'start', head, writing, commit}}
    for label, expected in predecessors.items():
        require({parent for parent in graph if label in edges[parent][0]} == expected, 'no premature commit or loop-entry bypass')
    require(set(graph) == {'start', *predecessors}, 'complete eight-block bulk loop inventory')
    stores = [(label, line) for label, block in graph.items() for line in block if line.startswith('store ')]
    require(len(stores) == 1 and stores[0][0] == commit, 'only direct memory store occurs after complete success')
    return trace, (preheader, setup, head, progress, returning), (writing, commit), rate


def cases(record):
    fills = {}
    for function, definitions, wipes in ownership.active.terminal.entry.reader.cases(record):
        _, _, secret = ownership.active.terminal.entry.reader.inspect(function, definitions, wipes)
        for name, body in definitions.items():
            if '14squeeze_secret' not in name or '@' + name + '(' not in definitions[secret]:
                continue
            selected = [callee for callee in definitions if '12fill_staging' in callee and '@' + callee + '(' in body]
            require(len(selected) == 1, 'unique actual defined fill dependency')
            fills[body] = selected[0]
    for case in ownership.cases(record):
        if '14squeeze_secret' in case[0].splitlines()[0]:
            require(case[0] in fills, 'bulk loop belongs to reader-bound dependency artifact')
            yield (*case, fills[case[0]])


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*case) for case in cases(record)]
    require(len(checks) == 16 and before == comparison.capture.sources(), 'complete unchanged bulk-progress matrix')
    print('Bulk squeeze: 16 bodies; exact bounded fill/write chunks and decreasing remainder; counter-commit block reachable only on complete success PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Loop/control routing only; counter decoding/addition/serialization, fill contents and whole-call register/spill erasure remain separate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
