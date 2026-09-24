#!/usr/bin/env python3
"""Bind retained borrowed-reader completion to the actual owned output result."""
import argparse
import json
from pathlib import Path
import re

import check_sha3_squeeze_error as errors
import check_secret_output_finish as finish
import check_volatile_clear_assembly as clearing

active = errors.active
adapter = errors.adapter
comparison = errors.comparison
require = errors.require
SSA = errors.SSA


def assigned(line, pattern, label):
    match = re.fullmatch('(' + SSA + ') = ' + pattern, line)
    require(match is not None, label)
    return match[1]


def gep(line, base, offset):
    return assigned(line, 'getelementptr inbounds nuw i8, ptr ' + re.escape(base) + ', i64 ' + str(offset),
                    'exact original descriptor field')


def lifetime(line, kind, slot, width):
    name, args = adapter.routes.guard.call(line)
    require(line.startswith('call void @') and name == 'llvm.lifetime.' + kind + '.p0' and args in
            (['ptr nonnull ' + slot], [f'i64 {width}', 'ptr nonnull ' + slot]), 'exact descriptor lifetime boundary')


def inspect(function, begin, wipes, drop, callees, headers, completion):
    trace, error_labels, marker = errors.inspect(function, begin, wipes, drop, callees, headers)
    _, active_labels, _, (work, _, _) = active.inspect(function, begin, wipes, drop, callees)
    _, _, origin = adapter.routes.transfer.finish.graph_info(function)
    graph = trace.graph
    start = trace.edges[error_labels[0]][0][0]
    require(trace.edges[active_labels[0]][0][1] == start, 'empty operation enters the same completion decision')
    lines = active.clean(graph[start])
    old = marker == '5'
    require(len(lines) == (4 if old else 3), 'closed completion ownership decision')
    present = assigned(lines[0], 'load i64, ptr ' + re.escape(work) + ', align 8', 'original operation ownership')
    flag = assigned(lines[-2], 'trunc nuw i64 ' + re.escape(present) + ' to i1', 'owned output presence')
    tested, owned, empty = adapter.shape.branch(trace, start)
    require(tested == flag and owned != empty, 'only owned output is finalized')
    block = graph[owned]
    require(len(block) == (5 if old else 6), 'closed initialization transfer and finish call')
    source = gep(block[0], work, 8)
    copying = block[1 if old else 2]
    name, args = adapter.routes.guard.call(copying)
    require(copying.startswith('call void @') and name == 'llvm.memcpy.p0.p0.i64' and len(args) == 4 and comparison.pointer(args[1]) == source
            and args[2:] == ['i64 24', 'i1 false'], 'complete original initialization descriptor transfer')
    initialization = comparison.pointer(args[0])
    require(initialization + ' = alloca [24 x i8], align 8' in graph['start'], 'bounded moved initialization handle')
    lifetime(lines[1] if old else block[1], 'start', initialization, 24)
    call = block[-2]
    name, args = adapter.routes.guard.call(call)
    require(call.startswith('invoke void @') and name == completion and len(args) == 2
            and 'sret([24 x i8])' in args[0] and comparison.pointer(args[1]) == initialization,
            'verified finish callee receives the original moved initialization')
    result = re.search('(' + SSA + ')$', args[0])
    require(result is not None and result[1] + ' = alloca [24 x i8], align 8' in graph['start']
            and result[1] != initialization, 'distinct bounded completion result')
    result = result[1]
    lifetime(block[-3], 'start', result, 24)
    decision, unwind = trace.edges[owned][0]
    require(unwind == trace.edges[error_labels[3]][0][1], 'completion unwind uses verified owner cleanup')
    decision_block = graph[decision]
    require(len(decision_block) == 3, 'closed actual finish-result decision')
    value = assigned(decision_block[0], 'load i8, ptr ' + re.escape(result) + ', align 8', 'actual finish discriminator')
    flag = assigned(decision_block[1], 'trunc nuw i8 ' + re.escape(value) + ' to i1', 'finish error flag')
    tested, rejected, accepted = adapter.shape.branch(trace, decision)
    require(tested == flag and rejected != accepted, 'only successfully owned output is returned')
    success = graph[accepted]
    require(len(success) == (6 if old else 12), 'closed owned result extraction')
    field = gep(success[0], result, 8)
    pointer = assigned(success[1], 'load ptr, ptr ' + re.escape(field) + ', align 8', 'finished original output pointer')
    field = gep(success[2], result, 16)
    length = assigned(success[3], 'load i64, ptr ' + re.escape(field) + ', align 8', 'finished full output length')
    lifetime(success[4], 'end', result, 24)
    require(len(trace.edges[accepted][0]) == 1, 'one successful output continuation')
    resume = trace.edges[accepted][0][0]
    require(success[-1] == 'br label %' + resume, 'success continues directly to reader reactivation')
    resumed = graph[resume]
    if old:
        require(empty == resume and len(resumed) == 12, 'shared empty/owned successful descriptor return')
        disc = assigned(resumed[0], r'phi i64 \[ 0, %' + re.escape(start) + r' \], \[ 1, %'
                        + re.escape(accepted) + r' \]', 'empty or owned successful discriminator')
        extent = assigned(resumed[1], r'phi i64 \[ undef, %' + re.escape(start) + r' \], \[ '
                          + re.escape(length) + ', %' + re.escape(accepted) + r' \]', 'owned length preserved')
        address = assigned(resumed[2], r'phi ptr \[ undef, %' + re.escape(start) + r' \], \[ '
                           + re.escape(pointer) + ', %' + re.escape(accepted) + r' \]', 'owned pointer preserved')
        lifetime(resumed[3], 'end', initialization, 24)
        lifetime(resumed[4], 'end', work, 48)
        flag_store = resumed[5]
        require(resumed[6] == f'store i64 {disc}, ptr %_0, align 8', 'success discriminator reaches original result')
        field = gep(resumed[7], '%_0', 8)
        require(resumed[8] == f'store ptr {address}, ptr {field}, align 8', 'owned pointer reaches caller')
        field = gep(resumed[9], '%_0', 16)
        require(resumed[10] == f'store i64 {extent}, ptr {field}, align 8', 'owned length reaches caller')
    else:
        field = gep(success[5], '%_0', 8)
        require(success[6] == f'store ptr {pointer}, ptr {field}, align 8', 'owned pointer reaches caller')
        field = gep(success[7], '%_0', 16)
        require(success[8:10] == [f'store i64 {length}, ptr {field}, align 8', 'store i64 1, ptr %_0, align 8'],
                'full length and owned successful result')
        lifetime(success[10], 'end', initialization, 24)
        require(graph[empty] == ['store i64 0, ptr %_0, align 8', 'br label %' + resume],
                'empty success exposes no output pointer or length')
        require(len(resumed) == 3, 'closed success reactivation')
        lifetime(resumed[0], 'end', work, 48)
        flag_store = resumed[1]
    flag = re.fullmatch(r'store i8 1, ptr (' + SSA + '), align 8', flag_store)
    require(flag is not None and origin(flag[1]) == ('%self', 8), 'reactivate only original reader on success')
    require(resumed[-1] == 'br label %' + error_labels[5], 'success enters checked descriptor exit and return')
    failure = graph[rejected]
    require(len(failure) == (3 if old else 6), 'closed failed-completion owner cleanup')
    lifetime(failure[0], 'end', result, 24)
    if not old:
        field = gep(failure[1], '%_0', 8)
        require(failure[2:4] == [f'store i8 4, ptr {field}, align 8', 'store i64 2, ptr %_0, align 8'],
                'failed completion becomes SecretMemory error, never success')
    else:
        require(', %' + rejected + ' ],' in graph[error_labels[4]][0], 'failed completion uses checked SecretMemory phi input')
    lifetime(failure[-2], 'end', initialization, 24)
    require(failure[-1] == 'br label %' + error_labels[4], 'failed completion enters original-owner wipe')
    labels = tuple(dict.fromkeys((start, owned, decision, rejected, accepted, empty, resume)))
    require(len(labels) == (6 if old else 7) and not set(labels) & set(error_labels), 'distinct complete output-completion slice')
    predecessors = {start: {active_labels[0], error_labels[0], error_labels[1]}, owned: {start},
                    decision: {owned}, rejected: {decision}, accepted: {decision},
                    resume: {start, accepted} if old else {empty, accepted}}
    if not old:
        predecessors[empty] = {start}
    for label, expected in predecessors.items():
        require({parent for parent in graph if label in trace.edges[parent][0]} == expected,
                'no alternate entry bypasses completion ownership or result checks')
    return trace, labels, (initialization, result, pointer, length), marker


def cases(record):
    completions = set()
    for row, _, core, assembly in comparison.cases(record):
        if row['profile'] != 'release':
            continue
        function = finish.select(core)
        finish.inspect(function)
        zero = clearing.llvm.select(core)
        clearing.llvm.inspect(zero)
        symbol = re.search(comparison.SYMBOL, zero.splitlines()[0])[1]
        calls = [re.search(comparison.SYMBOL, line)[1] for line in function.splitlines() if 'tail call' in line]
        require(calls == [symbol], 'finish cleanup binds the verified actual volatile callee')
        body = clearing.select(assembly)
        require(body.splitlines()[0] == symbol + ':', 'same emitted volatile-clear function')
        clearing.inspect(body, row['target'].startswith('aarch64'))
        completions.add(re.search(comparison.SYMBOL, function.splitlines()[0])[1])
    for case in errors.cases(record):
        matches = [name for name in completions if '@' + name + '(' in case[0]]
        require(len(matches) == 1, 'one verified retained completion callee in reader')
        yield (*case, matches[0])


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*case) for case in cases(record)]
    require(len(checks) == 16 and before == comparison.capture.sources(), 'complete unchanged output completion matrix')
    print('Output completion: 16 readers; original initialization, owned pointer/length and empty result preserved PASS')
    print('Failed completion requests original-owner wipe; bound core finish clears incomplete output through verified volatile callee')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Caller handoff only; squeeze semantics/descriptor preservation and whole-call register/spill erasure remain separate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
