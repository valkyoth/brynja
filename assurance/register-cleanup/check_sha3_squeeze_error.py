#!/usr/bin/env python3
"""Retained squeeze results: preserve errors and clean output before owner."""
import argparse
import json
from pathlib import Path
import re

import check_sha3_squeeze_unwind as unwind

active = unwind.active
adapter = active.adapter
comparison = active.comparison
require = active.require
SSA = active.SSA


def lifetime(line, slot, width):
    name, args = adapter.routes.guard.call(line)
    require(line.startswith('call void @') and name == 'llvm.lifetime.end.p0' and args in
            (['ptr nonnull ' + slot], [f'i64 {width}', 'ptr nonnull ' + slot]), 'exact local lifetime end')


def inspect(function, begin, wipes, drop, callees, headers):
    trace, unwind_labels = unwind.inspect(function, begin, wipes, drop, callees)
    _, _, routes, (work, output, owner) = active.inspect(function, begin, wipes, drop, callees)
    _, _, (_, _, original) = active.terminal.inspect(function, begin, wipes, drop)
    graph = trace.graph
    decisions = []
    markers = []
    for _, name, decision, _, value in routes:
        require(name in headers, 'source-bound squeeze result signature')
        signature = re.match(r'define internal fastcc noundef range\(i8 (-?\d+), (-?\d+)\) i8 @', headers[name])
        require(signature is not None and signature.groups() in (('0', '6'), ('-1', '5')),
                'reviewed retained compiler-private result range')
        # These are the retained Result<(), Error> layouts, not stable Rust ABI.
        marker = '5' if signature.groups() == ('0', '6') else '-1'
        lines = graph[decision]
        require(len(lines) == 2, 'closed squeeze-result decision')
        condition = re.fullmatch('(' + SSA + ') = icmp eq i8 ' + re.escape(value) + ', ' + marker, lines[0])
        tested, success, error = adapter.shape.branch(trace, decision)
        require(condition is not None and tested == condition[1] and success != error,
                'only the actual successful squeeze result enters completion')
        decisions.append((decision, success, error, value))
        markers.append(marker)
    require(markers[0] == markers[1] and decisions[0][1:3] == decisions[1][1:3],
            'bulk/final share result layout and success/error continuations')
    success, error = decisions[0][1:3]
    lines = graph[error]
    old_layout = markers[0] == '5'
    require(len(lines) == (6 if old_layout else 7), 'closed squeeze-error selection and ownership test')
    phi = re.fullmatch('(' + SSA + r') = phi i8 \[ ' + re.escape(decisions[0][3]) + ', %'
                       + re.escape(decisions[0][0]) + r' \], \[ ' + re.escape(decisions[1][3])
                       + ', %' + re.escape(decisions[1][0]) + r' \]', lines[0])
    require(phi is not None, 'error phi preserves the actual result from each squeeze call')

    def assigned(line, pattern, label):
        match = re.fullmatch('(' + SSA + ') = ' + pattern, line)
        require(match is not None, label)
        return match[1]

    if old_layout:
        wide = assigned(lines[1], 'zext nneg i8 ' + re.escape(phi[1]) + ' to i64', 'lossless unsigned error conversion')
        encoded = assigned(lines[2], 'inttoptr i64 ' + re.escape(wide) + ' to ptr', 'unchanged compiler-private error encoding')
    else:
        field = assigned(lines[1], r'getelementptr inbounds nuw i8, ptr %_0, i64 8', 'original caller error field')
        require(lines[2:4] == [f'store i8 {phi[1]}, ptr {field}, align 8', 'store i64 2, ptr %_0, align 8'],
                'original error byte and error result discriminator')
    present = assigned(lines[-3], 'load i64, ptr ' + re.escape(work) + ', align 8', 'original operation ownership')
    condition = assigned(lines[-2], 'icmp eq i64 ' + re.escape(present) + ', 0', 'only absent ownership skips Drop')
    tested, cleanup, dropping = adapter.shape.branch(trace, error)
    require(tested == condition and cleanup != dropping, 'present destination cleaned before owner')
    dropped = graph[dropping]
    require(len(dropped) == 2 and dropped[0].startswith('invoke void @'), 'one normal-error destination destructor')
    name, args = adapter.routes.guard.call(dropped[0])
    require(name == drop and len(args) == 1 and comparison.pointer(args[0]) == output,
            'bound destructor receives original operation output')
    require(trace.edges[dropping][0] == (cleanup, unwind_labels[3]),
            'Drop completes to owner wipe or unwinds through verified owner cleanup')
    cleaned = graph[cleanup]
    require(len(cleaned) == (7 if old_layout else 3), 'closed normal-error owner cleanup')
    if old_layout:
        merged = re.fullmatch('(' + SSA + r') = phi ptr \[ inttoptr \(i64 4 to ptr\), %(' + unwind.LABEL
                              + r') \], \[ ' + re.escape(encoded) + ', %' + re.escape(error)
                              + r' \], \[ ' + re.escape(encoded) + ', %' + re.escape(dropping) + r' \]', cleaned[0])
        require(merged is not None, 'error identity survives either destination-cleanup edge')
        lifetime(cleaned[1], work, 48)
        require(cleaned[2] == 'store i64 2, ptr %_0, align 8', 'error result cannot become success')
        field = assigned(cleaned[3], r'getelementptr inbounds nuw i8, ptr %_0, i64 8', 'original caller encoded error field')
        require(cleaned[4] == f'store ptr {merged[1]}, ptr {field}, align 8', 'returned error encoding unchanged')
    else:
        lifetime(cleaned[0], work, 48)
    name, args = adapter.routes.guard.call(cleaned[-2])
    require(cleaned[-2].startswith('call void @') and name in wipes and len(args) == 1
            and comparison.pointer(args[0]) == owner, 'bound original-owner wipe before normal error return')
    require(len(trace.edges[cleanup][0]) == 1, 'single cleanup exit')
    exit_label = trace.edges[cleanup][0][0]
    require(cleaned[-1] == 'br label %' + exit_label and len(graph[exit_label]) == 2,
            'cleanup enters only descriptor lifetime exit')
    lifetime(graph[exit_label][0], original, 48)
    require(len(trace.edges[exit_label][0]) == 1, 'single final error return')
    returning = trace.edges[exit_label][0][0]
    require(graph[exit_label][-1] == 'br label %' + returning and len(graph[returning]) == 2
            and graph[returning][-1] == 'ret void', 'error cannot reenter squeeze or successful completion')
    lifetime(graph[returning][0], '%length', 8)
    labels = (decisions[0][0], decisions[1][0], error, dropping, cleanup, exit_label, returning)
    require(len(set(labels)) == 7 and success not in labels, 'distinct error-only continuation')
    return trace, labels, markers[0]


def cases(record):
    signatures = {}
    for function, definitions, wipes in active.terminal.entry.reader.cases(record):
        _, _, secret = active.terminal.entry.reader.inspect(function, definitions, wipes)
        signatures[definitions[secret]] = {name: body.splitlines()[0] for name, body in definitions.items()}
    for case in active.cases(record):
        require(case[0] in signatures, 'result signatures from the same reader artifact')
        yield (*case, signatures[case[0]])


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*case) for case in cases(record)]
    require(len(checks) == 16 and before == comparison.capture.sources(), 'complete unchanged squeeze-result matrix')
    print('Squeeze results: 16 readers, 32 decisions, all five valid errors preserved; destination Drop then original-owner wipe PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Caller error routing only; callee result/ownership contract, successful completion and whole-call register/spill erasure remain separate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
