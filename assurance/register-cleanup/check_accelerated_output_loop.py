#!/usr/bin/env python3
"""Retained accelerated producer chunk progress, final mask and owned writes."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
from types import SimpleNamespace

import check_accelerated_completion as completion
import check_read_counter as counters
import check_secret_output_write as writing
import check_sha3_final_tail as tail

readers, adapter, comparison, require = completion.readers, completion.adapter, completion.comparison, completion.require
staging, SSA, assigned = completion.staging, completion.SSA, completion.assigned


@dataclass(frozen=True)
class Case:
    reader: readers.Case
    cpu: str


def admission(function, names, compiler, preheader, thorough=False):
    graph, edges, origin = adapter.routes.transfer.finish.graph_info(function)
    branch = lambda label: adapter.shape.branch(SimpleNamespace(graph=graph), label)
    incoming = lambda label: {p for p in graph if label in edges[p][0]}
    # The entry/ownership checker is composed by bind(). Select its final/bulk
    # dispatch from the original operation metadata, not from guessed labels.
    joins = [label for label, lines in graph.items() if lines and 'phi i1' in lines[0]
             and ', %start ]' in lines[0]]
    require(len(joins) == 1, 'one original final/bulk dispatch')
    join = joins[0]
    _, final, bulk = branch(join)
    lines = graph[bulk]
    require(len(lines) == 2 and len(edges[bulk][0]) == 1, 'closed bulk-length admission')
    bulk_length = assigned(lines[0], 'load i64, ptr %length, align 8')
    state_start = edges[bulk][0][0]
    require(lines[1] == 'br label %' + state_start, 'bulk enters common preflight')
    lines = graph[final]
    require(len(lines) == 6, 'closed final-bit empty-length check')
    valid_load = re.fullmatch('(' + SSA + r') = load i8, ptr (' + SSA + '), align 1', lines[0])
    require(valid_load is not None and origin(valid_load[2]) == ('%final_bits', 1), 'original valid-bit argument')
    valid = valid_load[1]
    final_length = assigned(lines[1], 'load i64, ptr %length, align 8')
    nonempty = assigned(lines[2], 'icmp ne i64 ' + re.escape(final_length) + ', 0')
    zero_valid = assigned(lines[3], 'icmp eq i8 ' + re.escape(valid) + ', 0')
    admissible = assigned(lines[4], 'or i1 ' + re.escape(zero_valid) + ', ' + re.escape(nonempty))
    tested, nonempty_check, error = branch(final)
    require(tested == admissible, 'empty final output requires zero valid bits')
    lines = graph[nonempty_check]
    require(len(lines) == 5, 'closed valid-bit range check')
    empty = assigned(lines[0], 'icmp eq i64 ' + re.escape(final_length) + ', 0')
    decremented = assigned(lines[1], 'add i8 ' + re.escape(valid) + ', -1')
    in_range = assigned(lines[2], 'icmp ult i8 ' + re.escape(decremented) + ', 8')
    admissible = assigned(lines[3], 'or i1 ' + re.escape(in_range) + ', ' + re.escape(empty))
    tested, admitted, invalid = branch(nonempty_check)
    require(tested == admissible and admitted == state_start and invalid == error, 'nonempty final output accepts only one through eight valid bits')
    original_length = assigned(graph[state_start][0], r'phi i64 \[ ' + re.escape(bulk_length) + ', %' + re.escape(bulk)
                               + r' \], \[ ' + re.escape(final_length) + ', %' + re.escape(nonempty_check) + r' \]')
    # Drop only the already-bound metadata phi when invoking the existing
    # bounded counter model; alpha-rename the owner parameter to its vocabulary.
    modeled = {label: [line.replace('%self.0.val', '%self') for line in lines] for label, lines in graph.items()}
    modeled[state_start] = modeled[state_start][1:]
    session_blocks = [(label, lines) for label, lines in graph.items()
                      if any('invoke ' in line and adapter.routes.guard.call(line)[0] == names['session'] for line in lines)]
    require(len(session_blocks) == 1 and len(session_blocks[0][1]) == 2, 'one preflight session check')
    session_block, lines = session_blocks[0]
    session_result = assigned(lines[0].split(' @', 1)[0], 'invoke noundef i8')
    after_session, unwind = staging.edges(lines[1])
    require(len(graph[after_session]) == 2, 'closed preflight authority decision')
    _, counter_block, session_error = branch(after_session)
    require(session_error == error and incoming(counter_block) == {after_session}
            and incoming(preheader) == {counter_block}, 'counter admission dominates loop entry')
    require(incoming(state_start) == {bulk, nonempty_check} and incoming(final) == incoming(bulk) == {join}
            and incoming(nonempty_check) == {final} and incoming(session_block) == {state_start}
            and incoming(after_session) == {session_block}, 'no preflight/metadata bypass')
    all_clear = {('wipe', 624, 234), ('clear', 864, 168), ('clear', 1056, 2), ('drop',)}
    env = {'%self.0.val': ('storage', 0), '%_0': ('result', 0), '%_10': ('init', 0)}
    initializers = [name for name in re.findall(SSA + r'(?= = getelementptr)', function) if origin(name) == ('%_10', 8)]
    require(len(initializers) == 1, 'one original initializer field')
    env[initializers[0]] = ('init', 8)
    for parent in (final, nonempty_check):
        staging.walk(graph, error, parent, env, names, True, all_clear, 'error')
    staging.walk(graph, unwind, session_block, env, names, True, all_clear, 'unwind')
    backend_success = 7 if compiler == '1.90.0' else 255
    # Check reconstruction itself, not merely sampled overflow decisions: many
    # different upper-byte values produce the same accept/reject result.
    additions = [line for line in graph[counter_block] if '@llvm.uadd.with.overflow.i128(' in line]
    complements = [line for line in graph[counter_block] if re.search(r' = xor i128 ', line)]
    if compiler == '1.90.0':
        require(len(additions) == 1 and not complements, 'one checked preflight addition')
        _, operands = adapter.routes.guard.call(additions[0])
        require(len(operands) == 2 and all(re.fullmatch('i128 ' + SSA, arg) for arg in operands), '128-bit counter and requested width')
        decoded, requested_width = (arg.split()[-1] for arg in operands)
    else:
        require(len(complements) == 1 and not additions, 'one unsigned capacity complement')
        matched = re.fullmatch(SSA + r' = xor i128 (' + SSA + '), -1', complements[0])
        require(matched is not None, 'complete 128-bit complement')
        decoded = matched[1]
        widths = [assigned(line, 'zext i64 ' + re.escape(original_length) + ' to i128')
                  for line in graph[counter_block] if 'zext i64 ' + original_length + ' to i128' in line]
        require(len(widths) == 1, 'one complete requested length extension')
        requested_width = widths[0]
    require(requested_width + ' = zext i64 ' + original_length + ' to i128' in graph[counter_block], 'original length in counter admission')
    count = 0
    for counter, length, failed, squeezing, revoked in counters.scenarios(thorough):
        state = dict(counter=counter, failed=failed, squeezing=squeezing,
                     session_result=2 if revoked else backend_success, checks=0, writes=[])
        values = {original_length: length}
        result = counters.evaluate(modeled, state_start, None, values, state,
                                   names['session'], dict(error=error, loop=preheader), False)
        code = 7 if failed or not squeezing else 2 if revoked else 8 if counter + length > counters.MAX else None
        require(state['checks'] == (0 if failed or not squeezing else 1) and not state['writes'], 'preflight revalidates before admission and never commits output')
        if not failed and squeezing and not revoked:
            require(values.get(decoded) == counter and values.get(requested_width) == length, 'all original counter bits and request length preserved')
        require(result[0] == 'loop' if code is None else result == ('error', code), 'terminal/revoked/overflow admission is fail-closed')
        count += 1
    return (bulk, final, nonempty_check, state_start, session_block, after_session, counter_block), count


def inspect(function, names, compiler):
    old = compiler == '1.90.0'
    graph, edges, origin = adapter.routes.transfer.finish.graph_info(function)
    branch = lambda label: adapter.shape.branch(SimpleNamespace(graph=graph), label)
    incoming = lambda label: {p for p in graph if label in edges[p][0]}
    completed = completion.inspect(function, names, compiler)[0]
    calls = {}
    for label, lines in graph.items():
        for i, line in enumerate(lines):
            if 'invoke ' not in line:
                continue
            name, args = adapter.routes.guard.call(line)
            for kind in ('read', 'write', 'mask', 'clear'):
                if name == names[kind]:
                    require(kind not in calls and i == len(lines) - 2, 'unique terminal producer invocation')
                    calls[kind] = (label, line, args, staging.edges(lines[-1]))
    require(set(calls) == {'read', 'write', 'mask', 'clear'}, 'complete read/mask/write/clear loop')
    head, read_call, read_args, (read_test, unwind) = calls['read']
    write, write_call, write_args, (write_test, write_unwind) = calls['write']
    masking, mask_call, mask_args, (mask_done, mask_unwind) = calls['mask']
    clearing, clear_call, clear_args, (progress, clear_unwind) = calls['clear']
    require(unwind == write_unwind == mask_unwind == clear_unwind, 'all loop invokes share cleanup')
    lines = graph[head]
    require(len(lines) == 4, 'closed read iteration')
    phi = re.fullmatch('(' + SSA + r') = phi i64 \[ (' + SSA + '), %(' + staging.LABEL
                       + r') \], \[ (' + SSA + '), %' + re.escape(progress) + r' \]', lines[0])
    require(phi is not None, 'remaining bytes begin with original length then exact progress')
    remaining, requested, setup, next_remaining = phi.groups()
    count = assigned(lines[1], r'call noundef i64 @llvm.umin.i64\(i64 ' + re.escape(remaining) + r', i64 168\)')
    require(re.match(SSA + r' = invoke fastcc noundef i8 @', read_call)
            and len(read_args) == 3 and comparison.pointer(read_args[0]) == '%self.0.val'
            and read_args[2] == 'i64 noundef ' + count, 'actual read uses original storage and current bounded count')
    stage = comparison.pointer(read_args[1])
    lines = graph[setup]
    require(len(lines) == (3 if old else 2) and lines[-1] == 'br label %' + head, 'closed nonempty loop setup')
    require(completion.gep(lines[0], '%self.0.val', 864) == stage, 'original full staging region')
    if old:
        before_stage = completion.gep(lines[1], '%self.0.val', 863)
    parents = incoming(setup)
    require(len(parents) == 1, 'one zero-length decision')
    preheader = next(iter(parents))
    lines = graph[preheader]
    require(len(lines) == 3 and lines[0] == requested + ' = load i64, ptr %length, align 8', 'original destination length at loop entry')
    zero = assigned(lines[1], 'icmp eq i64 ' + re.escape(requested) + ', 0')
    tested, empty, nonempty = branch(preheader)
    require(tested == zero and empty == completed and nonempty == setup, 'zero skips all iteration; nonzero initializes remaining')

    def success_test(label, invocation, success):
        lines = graph[label]
        require(len(lines) == 2, 'closed call-result decision')
        value = assigned(invocation.split(' @', 1)[0], r'invoke (?:fastcc )?noundef i8')
        check = assigned(lines[0], 'icmp eq i8 ' + re.escape(value) + ', ' + success)
        tested, accepted, rejected = branch(label)
        require(tested == check and accepted != rejected, 'only actual call success advances')
        return accepted, rejected, value

    choose_tail, read_error, read_value = success_test(read_test, read_call, '12' if old else '-1')
    cleared, write_error, write_value = success_test(write_test, write_call, '4' if old else '-1')
    require(cleared == clearing and read_error == write_error, 'write success clears stage; read/write errors use one failure path')
    lines = graph[choose_tail]
    require(len(lines) == 2, 'closed last-chunk decision')
    last = assigned(lines[0], 'icmp ult i64 ' + re.escape(remaining) + ', 169')
    tested, choose_mode, choose_owner = branch(choose_tail)
    require(tested == last, 'only final chunk may be masked')
    lines = graph[choose_mode]
    require(len(lines) == 4, 'closed original final-mode selection')
    mode_address = re.fullmatch('(' + SSA + r') = load ptr, ptr (' + SSA + '), align 8', lines[0])
    require(mode_address is not None and origin(mode_address[2]) == ('%_10', 32), 'mode reference comes from original operation metadata')
    mode_pointer = mode_address[1]
    mode = assigned(lines[1], 'load i8, ptr ' + re.escape(mode_pointer) + ', align 1')
    flag = assigned(lines[2], 'trunc nuw i8 ' + re.escape(mode) + ' to i1')
    tested, tail_entry, ordinary = branch(choose_mode)
    require(tested == flag and ordinary == choose_owner, 'bulk output bypasses tail mask')
    lines = graph[masking]
    require(len(lines) == (7 if old else 9), 'closed final-byte mask')
    valid_address = completion.gep(lines[0], mode_pointer, 1)
    valid = assigned(lines[1], 'load i8, ptr ' + re.escape(valid_address) + ', align 1')
    if old:
        require(tail_entry != masking and len(graph[tail_entry]) == 3, 'old compiler has explicit final-byte presence guard')
        tail_lines = graph[tail_entry]
        final_byte = assigned(tail_lines[0], 'getelementptr i8, ptr ' + re.escape(before_stage) + ', i64 ' + re.escape(count))
        absent = assigned(tail_lines[1], 'icmp eq ptr ' + re.escape(final_byte) + ', null')
        tested, rejected, ready = branch(tail_entry)
        require(tested == absent and rejected == read_error and ready == masking, 'missing final byte rejects before mask')
        offset = 2
    else:
        require(tail_entry == masking, 'new compiler directly masks proved-nonempty chunk')
        end = assigned(lines[2], 'getelementptr i8, ptr ' + re.escape(stage) + ', i64 ' + re.escape(count))
        final_byte = assigned(lines[3], 'getelementptr i8, ptr ' + re.escape(end) + ', i64 -1')
        offset = 4
    shift = assigned(lines[offset], r'call i8 @llvm.usub.sat.i8\(i8 8, i8 ' + re.escape(valid) + r'\)')
    bounded_shift = assigned(lines[offset + 1], 'and i8 ' + re.escape(shift) + ', 7')
    keep = assigned(lines[offset + 2], 'lshr i8 -1, ' + re.escape(bounded_shift))
    require(mask_call.startswith('invoke void @') and len(mask_args) == 3 and comparison.pointer(mask_args[0]) == final_byte
            and mask_args[1:] == ['i8 noundef ' + keep, 'i8 noundef 0'] and mask_done == choose_owner, 'mask actual last staged byte before owned write')
    lines = graph[choose_owner]
    require(len(lines) == 3, 'closed initializer presence check')
    presence = assigned(lines[0], 'load i64, ptr %_10, align 8')
    present = assigned(lines[1], 'trunc nuw i64 ' + re.escape(presence) + ' to i1')
    tested, owned, owner_error = branch(choose_owner)
    require(tested == present and owned == write and owner_error not in {head, progress, completed}, 'only present initialization can receive staged output')
    require(len(graph[write]) == len(graph[clearing]) == 2 and len(write_args) == 3
            and origin(comparison.pointer(write_args[0])) == ('%_10', 8)
            and comparison.pointer(write_args[1]) == stage and write_args[2] == 'i64 noundef ' + count, 'write exact freshly staged chunk into original initializer')
    require(len(clear_args) == 2 and comparison.pointer(clear_args[0]) == stage and clear_args[1] == 'i64 noundef 168', 'full staging cleared before progress')
    lines = graph[progress]
    require(len(lines) == 3 and lines[0] == f'{next_remaining} = sub nuw i64 {remaining}, {count}', 'advance by exactly successfully written chunk')
    exhausted = assigned(lines[1], 'icmp eq i64 ' + re.escape(next_remaining) + ', 0')
    tested, done, again = branch(progress)
    require(tested == exhausted and done == completed and again == head, 'finish on exact exhaustion, otherwise repeat positive remainder')
    parents = {setup: {preheader}, head: {setup, progress}, read_test: {head}, choose_tail: {read_test},
               choose_mode: {choose_tail}, choose_owner: {choose_tail, choose_mode, masking},
               masking: {tail_entry} if old else {choose_mode}, write: {choose_owner}, write_test: {write},
               clearing: {write_test}, progress: {clearing}, completed: {preheader, progress}}
    if old:
        parents[tail_entry] = {choose_mode}
    for label, expected in parents.items():
        require(incoming(label) == expected, 'no skipped read/mask/write/clear or premature completion')
    # Existing cleanup model covers read/write rejection. Also exercise mask,
    # clear unwind and missing-initializer rejection using the same owned paths.
    env = {'%self.0.val': ('storage', 0), '%_0': ('result', 0), '%_10': ('init', 0), presence: 0,
           comparison.pointer(write_args[0]): ('init', 8)}
    required = {('wipe', 624, 234), ('clear', 864, 168), ('clear', 1056, 2)}
    staging.walk(graph, owner_error, choose_owner, env, names, True, required, 'error')
    staging.walk(graph, unwind, masking, env, names, True, required | {('drop',)}, 'unwind')
    if old:
        staging.walk(graph, read_error, tail_entry, env, names, True, required | {('drop',)}, 'error')
    admission_labels, _ = admission(function, names, compiler, preheader)
    return tuple(dict.fromkeys((preheader, setup, head, read_test, choose_tail, choose_mode, tail_entry,
                               masking, choose_owner, write, write_test, clearing, progress, *admission_labels)))


def bind(case, thorough=True):
    reader = case.reader
    function, names, compiler = completion.bind(reader)
    definitions = comparison.definitions(reader.core)
    names.update(read=staging.unique(comparison.definitions(reader.sha3), 'accelerated', '6Engine4read'),
                 write=staging.unique(definitions, 'Initialization5write'),
                 mask=staging.unique(definitions, '22apply_secret_byte_mask'),
                 session=staging.unique(comparison.definitions(case.cpu), '13KeccakSession5check'))
    count = counters.inspect(reader.sha3, reader.core, case.cpu, compiler, thorough)
    writer = definitions[names['write']]
    writing.inspect(writer, compiler)
    copy = staging.unique(definitions, 'secret_memory_transfer10copy_bytes')
    calls = [adapter.routes.guard.call(line.strip())[0] for line in writer.splitlines() if 'tail call fastcc void @' in line]
    require(calls == [copy] and re.search(r'^' + re.escape(copy) + ':', reader.assembly, re.M), 'actual same-row output-copy dependency')
    writing.copy_boundary.inspect(reader.assembly, reader.arm)
    _, zero = completion.entry.beginning.select(reader.core)
    readers.chain.dropping.inspect(definitions[names['drop']], zero)
    tail.dependency(reader.core, reader.assembly, reader.arm)
    staging.inspect(reader.sha3, reader.core, compiler)
    return function, names, compiler, count


def cases(record):
    dependencies = list(counters.read.cases(record))
    for reader in readers.cases(record):
        matched = [cpu for sha3, core, cpu, compiler in dependencies
                   if sha3 == reader.sha3 and core == reader.core and compiler == reader.compiler]
        require(len(matched) == 1, 'unique source-bound same-configuration read dependency')
        yield Case(reader, matched[0])


def main(record):
    before = comparison.capture.sources()
    results = []
    for case in cases(record):
        function, names, compiler, count = bind(case)
        labels = inspect(function, names, compiler)
        _, preflight_count = admission(function, names, compiler, labels[0], True)
        results.append((labels, count, preflight_count))
    require(len(results) == 8 and before == comparison.capture.sources(), 'complete unchanged optimized loop matrix')
    print(f'Accelerated producer loop: eight instantiated paths PASS; {sum(count for _, count, _ in results)} engine and {sum(count for _, _, count in results)} producer preflight cases')
    print('Bounded original staging, last-byte-only mask, checked owned writes and clear-before-progress/completion')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Original valid-bit admission and preflight bound; no all-input formal proof, debug, whole-call erasure or native Arm claim')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
