#!/usr/bin/env python3
"""Retained accelerated output completion and cleanup, not full producer proof."""
import argparse
import json
from pathlib import Path
import re
from types import SimpleNamespace

import check_accelerated_initialization as entry
import check_secret_output_finish as finishing

readers, adapter, comparison, require = entry.readers, entry.adapter, entry.comparison, entry.require
staging, SSA = readers.staging, entry.SSA
assigned, lifetime = readers.assigned, entry.lifetime


def gep(line, base, offset):
    return assigned(line, 'getelementptr inbounds nuw i8, ptr ' + re.escape(base) + ', i64 ' + re.escape(str(offset)))


def inspect(function, names, compiler):
    require(compiler in ('1.90.0', '1.98.1'), 'reviewed completion compiler')
    old = compiler == '1.90.0'
    graph, edges, origin = adapter.routes.transfer.finish.graph_info(function)
    branch = lambda label: adapter.shape.branch(SimpleNamespace(graph=graph), label)
    incoming = lambda label: {parent for parent in graph if label in edges[parent][0]}
    matches = [(label, line) for label, lines in graph.items() for line in lines
               if 'invoke void @' in line and adapter.routes.guard.call(line)[0] == names['finish']]
    require(len(matches) == 1, 'one actual completion invocation')
    owned, call = matches[0]
    parents = incoming(owned)
    require(len(parents) == 1, 'only presence decision enters completion')
    start = next(iter(parents))
    lines = graph[start]
    require(len(lines) == (4 if old else 3), 'closed ownership presence decision')
    present = assigned(lines[0], 'load i64, ptr %_10, align 8')
    flag = assigned(lines[-2], 'trunc nuw i64 ' + re.escape(present) + ' to i1')
    tested, have_output, empty = branch(start)
    require(tested == flag and have_output == owned and empty != owned, 'only present output is finished')
    block = graph[owned]
    require(len(block) == (4 if old else 5) and block[-2] == call, 'closed moved initialization and finish')
    copying = block[0 if old else 1]
    name, args = adapter.routes.guard.call(copying)
    require(copying.startswith('call void @') and name == 'llvm.memcpy.p0.p0.i64'
            and len(args) == 4 and args[2:] == ['i64 24', 'i1 false'], 'complete 24-byte ownership move')
    moved, source = comparison.pointer(args[0]), comparison.pointer(args[1])
    require(origin(source) == ('%_10', 8) and moved + ' = alloca [24 x i8], align 8' in graph['start'], 'original bounded initialization descriptor')
    lifetime(lines[1] if old else block[0], 'start', moved, 24)
    name, args = adapter.routes.guard.call(call)
    require(name == names['finish'] and len(args) == 2 and 'sret([24 x i8])' in args[0]
            and comparison.pointer(args[1]) == moved, 'actual finish receives original moved ownership')
    result_match = re.search('(' + SSA + ')$', args[0])
    require(result_match is not None, 'named finish result')
    result = result_match[1]
    require(result != moved and result + ' = alloca [24 x i8], align 8' in graph['start'], 'distinct bounded finish result')
    lifetime(block[-3], 'start', result, 24)
    decision, unwind = staging.edges(block[-1])
    block = graph[decision]
    require(len(block) == 3, 'closed finish discriminator test')
    value = assigned(block[0], 'load i8, ptr ' + re.escape(result) + ', align 8')
    error = assigned(block[1], 'trunc nuw i8 ' + re.escape(value) + ' to i1')
    tested, rejected, accepted = branch(decision)
    require(tested == error and rejected != accepted, 'failed completion cannot become output success')

    block = graph[accepted]
    require(len(block) == (6 if old else 7), 'closed successful output extraction')
    pointer_field = gep(block[0], result, 8)
    pointer = assigned(block[1], 'load ptr, ptr ' + re.escape(pointer_field) + ', align 8')
    length_field = gep(block[2], result, 16)
    length = assigned(block[3], 'load i64, ptr ' + re.escape(length_field) + ', align 8')
    lifetime(block[4], 'end', result, 24)
    if not old:
        lifetime(block[5], 'end', moved, 24)
    require(block[-1] == 'br label %' + empty, 'owned and absent output share successful return')
    block = graph[empty]
    require(len(block) == (10 if old else 9), 'closed result construction')
    phis = {}
    expected = {('i64', '0', '1'): 'discriminator', ('i64', 'undef', length): 'length', ('ptr', 'undef', pointer): 'pointer'}
    for line in block[:3]:
        match = re.fullmatch('(' + SSA + r') = phi (ptr|i64) (.+)', line)
        require(match is not None, 'result metadata phi')
        pairs = re.findall(r'\[ ([^,]+), %(' + staging.LABEL + r') \]', match[3])
        require(len(pairs) == 2 and {p for _, p in pairs} == {start, accepted}, 'only empty and finished predecessors')
        values = {p: value for value, p in pairs}
        key = (match[2], values[start], values[accepted])
        require(key in expected and expected[key] not in phis, 'exact empty/finished pointer, length, discriminator')
        phis[expected[key]] = match[1]
    index = 3
    if old:
        lifetime(block[index], 'end', moved, 24)
        index += 1
    require(block[index] == f'store i64 {phis["discriminator"]}, ptr %_0, align 8', 'success discriminator reaches original result')
    pointer_field = gep(block[index + 1], '%_0', 8)
    length_field = gep(block[index + 3], '%_0', 16)
    require(block[index + 2] == f'store ptr {phis["pointer"]}, ptr {pointer_field}, align 8'
            and block[index + 4] == f'store i64 {phis["length"]}, ptr {length_field}, align 8', 'finished original pointer and complete extent returned')
    require(len(edges[empty][0]) == 1, 'one success cleanup continuation')
    cleanup = edges[empty][0][0]
    require(block[-1] == 'br label %' + cleanup, 'success directly requests staging clear')

    block = graph[rejected]
    require(len(block) == (6 if old else 3), 'closed failed finish mapping')
    lifetime(block[0], 'end', result, 24)
    lifetime(block[1], 'end', moved, 24)
    if old:
        failure_block = block[2:]
    else:
        require(len(edges[rejected][0]) == 1, 'failed finish has one error mapping')
        mapping = edges[rejected][0][0]
        require(block[-1] == 'br label %' + mapping, 'failed finish reaches error mapping directly')
        failure_block = graph[mapping]
    require(len(failure_block) == 4, 'closed SecretMemory error mapping')
    error_field = gep(failure_block[0], '%_0', 8)
    require(failure_block[1:3] == [f'store i8 10, ptr {error_field}, align 8', 'store i64 2, ptr %_0, align 8'], 'failure remains SecretMemory error')
    match = re.fullmatch('br label %(' + staging.LABEL + ')', failure_block[-1])
    require(match is not None, 'error cleanup continuation')
    failed_cleanup = match[1]
    block = graph[failed_cleanup]
    require(len(block) == 9 and block[-1] == 'br label %' + cleanup, 'closed failed-operation cleanup')
    failed_flag = gep(block[0], '%self.0.val', 859)
    cursor = gep(block[2], '%self.0.val', 616)
    require(block[1] == f'store i8 1, ptr {failed_flag}, align 1'
            and block[3] == f'store i64 0, ptr {cursor}, align 8', 'failed operation terminates original engine and resets cursor')
    block = graph[cleanup]
    require(len(block) == 6, 'closed success/error cleanup selector')
    offset = assigned(block[0], r'phi i64 \[ 1056, %' + re.escape(failed_cleanup) + r' \], \[ 864, %' + re.escape(empty) + r' \]')
    extent = assigned(block[1], r'phi i64 \[ 2, %' + re.escape(failed_cleanup) + r' \], \[ 168, %' + re.escape(empty) + r' \]')
    region = gep(block[2], '%self.0.val', offset)
    name, args = adapter.routes.guard.call(block[3])
    require(re.match(SSA + r' = call noundef i8 @', block[3]) and name == names['clear'] and len(args) == 2
            and comparison.pointer(args[0]) == region and args[1] == 'i64 noundef ' + extent, 'exact predecessor-selected original region clearing')
    lifetime(block[4], 'end', '%_10', 48)
    require(len(edges[cleanup][0]) == 1, 'one cleaned return')
    returning = edges[cleanup][0][0]
    require(block[5] == 'br label %' + returning and len(graph[returning]) == 2
            and graph[returning][1] == 'ret void', 'no output changes after completion cleanup')
    lifetime(graph[returning][0], 'end', '%length', 8)

    # Reuse the closed cleanup interpreter and same-row checked guard body.
    env = {'%self.0.val': ('storage', 0), '%_0': ('result', 0)}
    all_clear = {('wipe', 624, 234), ('clear', 864, 168), ('clear', 1056, 2)}
    staging.walk(graph, rejected, decision, env, names, True, all_clear, 'error')
    staging.walk(graph, cleanup, empty, env, names, True, {('clear', 864, 168)}, 'guard')

    block = graph[unwind]
    require(len(block) == 3 and block[1] == 'cleanup' and len(edges[unwind][0]) == 1, 'original completion landing pad')
    exception = assigned(block[0], r'landingpad \{ ptr, i32 \}')
    guard_block = edges[unwind][0][0]
    require(block[-1] == 'br label %' + guard_block, 'completion unwind enters operation guard')
    block = graph[guard_block]
    require(len(block) == 3, 'closed unwind guard dispatch')
    exception_phi = re.fullmatch('(' + SSA + r') = phi \{ ptr, i32 \} (.+)', block[0])
    require(exception_phi is not None, 'exception phi')
    pairs = re.findall(r'\[ (' + SSA + r'), %(' + staging.LABEL + r') \]', exception_phi[2])
    require(len(pairs) == 3 and len({p for _, p in pairs}) == 3
            and [(value, parent) for value, parent in pairs if parent == unwind] == [(exception, unwind)], 'completion exception preserved in shared cleanup')
    name, args = adapter.routes.guard.call(block[1])
    require(block[1].startswith('invoke fastcc void @') and name == names['guard']
            and args == ['ptr nonnull %self.0.val', 'i8 0'], 'unwind invokes incomplete original operation guard')
    resumed, abort = staging.edges(block[2])
    require(graph[resumed] == ['resume { ptr, i32 } ' + exception_phi[1]], 'original completion exception resumes')
    block = graph[abort]
    require(len(block) == 4 and block[1] == 'filter [0 x ptr] zeroinitializer' and block[-1] == 'unreachable', 'double-panic nonreturning boundary')
    assigned(block[0], r'landingpad \{ ptr, i32 \}')
    name, args = adapter.routes.guard.call(block[2])
    require(block[2].startswith('call void @') and '16panic_in_cleanup' in name and args == [''], 'only identified double-panic termination excluded')
    staging.walk(graph, unwind, owned, env, names, True, all_clear, 'unwind')

    for label, expected in ((owned, {start}), (decision, {owned}), (accepted, {decision}),
                            (rejected, {decision}), (empty, {start, accepted}), (cleanup, {empty, failed_cleanup})):
        require(incoming(label) == expected, 'no alternate entry bypasses ownership/completion checks')
    labels = [start, owned, decision, accepted, rejected, empty, cleanup, failed_cleanup, unwind, guard_block, resumed, abort, returning]
    if not old:
        labels.append(mapping)
    require(len(set(labels)) == len(labels), 'distinct completion and cleanup blocks')
    return tuple(labels)


def bind(case):
    function, begin, wipe, clear, arm = entry.bind(case)
    entry.inspect(function, begin, wipe, clear, arm)
    finish = finishing.select(case.core)
    finishing.inspect(finish)
    _, zero = entry.beginning.select(case.core)
    calls = [adapter.routes.guard.call(line.strip())[0] for line in finish.splitlines() if 'tail call fastcc void @' in line]
    require(calls == [zero], 'actual completion cleanup uses same-row volatile implementation')
    definitions = comparison.definitions(case.sha3)
    guard = staging.unique({name: body for name, body in definitions.items() if 'drop_in_place' in name or 'drop_glue' in name}, 'xof', 'Operation')
    names = {'finish': readers.chain.symbol(finish), 'wipe': wipe, 'clear': clear, 'guard': guard,
             'drop': staging.unique(comparison.definitions(case.core), 'SecretRegionInitialization', '4drop')}
    for flag in (0, 1):
        staging.walk(staging.graph(definitions[guard]), 'start', None,
                     {'%_1.0.val': ('storage', 0), '%_1.8.val': flag}, names, False,
                     {('clear', 864, 168)} if flag else {('wipe', 624, 234), ('clear', 864, 168), ('clear', 1056, 2)}, 'guard')
    return function, names, case.compiler


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*bind(case)) for case in readers.cases(record)]
    require(len(checks) == 8 and before == comparison.capture.sources(), 'complete unchanged optimized completion matrix')
    print('Accelerated output completion: eight instantiated paths PASS; original descriptor returned only after successful finish')
    print('Empty output remains absent; failed finish clears owned storage; recoverable unwind preserves exception and cleanup')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Completion boundary only; admission/loop correctness, debug, register/spill and native Arm qualification remain separate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
