#!/usr/bin/env python3
"""Retained accelerated read-loop bounds/cleanup requests, not whole-call erasure."""
import argparse
import json
from pathlib import Path
import re

import check_accelerated_staging as shared

comparison = shared.comparison
require = comparison.require
match = shared.writing.match
SSA, LABEL = shared.SSA, shared.LABEL


def conditional(body, value, success):
    require(len(body) == 2, 'closed read result branch')
    predicate = match('(' + SSA + ') = icmp eq i8 ' + re.escape(value) + ', ' + str(success), body[0])[1]
    return match('br i1 ' + re.escape(predicate) + ', label %(' + LABEL + '), label %(' + LABEL + ')', body[1]).groups()


def pointer_at(function, name, offset):
    require(re.search(re.escape(name) + r' = getelementptr inbounds nuw i8, ptr %self, i64 '
                      + str(offset) + r'(?:\n|, !)', function), 'exact read owner field: ' + str(offset))


def inspect(sha3, core, cpu, compiler):
    require(compiler in ('1.90.0', '1.98.1'), 'reviewed read compiler')
    old = compiler == '1.90.0'
    definitions = comparison.definitions(sha3)
    function = definitions[shared.unique(definitions, 'accelerated', '6Engine4read')]
    blocks = shared.graph(function)
    names = {
        'copy': shared.unique(comparison.definitions(core), '18copy_secret_region'),
        'permute': shared.unique(comparison.definitions(cpu), '13KeccakSession7permute'),
        'wipe': shared.unique(definitions, 'accelerated', '6Memory4wipe'),
    }
    header = function.splitlines()[0]
    params = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    require(len(params) == 3 and comparison.pointer(params[0]) == '%self', 'borrowed accelerated read ABI')
    destination = comparison.pointer(params[1])
    length = re.search(SSA + '$', params[2])[0]
    calls = {}
    for label, body in blocks.items():
        for index, line in enumerate(body):
            if 'invoke ' in line:
                name, args = shared.invocation(line)
                for kind in ('copy', 'permute'):
                    if name == names[kind]:
                        require(kind not in calls and index == len(body) - 2, 'unique terminating copy/permutation invoke')
                        result = match('(' + SSA + r') = invoke noundef i8 ', line[:re.search(comparison.SYMBOL, line).start()])[1]
                        calls[kind] = label, body, args, result, shared.edges(body[-1])
    require(set(calls) == {'copy', 'permute'}, 'complete read copy/permutation inventory')
    copy_label, copying, args, copied, (copy_result, unwind) = calls['copy']
    require(len(copying) == 3 and len(args) == 4 and args[1] == args[3], 'closed equal-slice copy block')
    target, source = comparison.pointer(args[0]), comparison.pointer(args[2])
    count = match('i64 noundef (' + SSA + ')', args[1])[1]
    source_gep = match(re.escape(source) + r' = getelementptr inbounds nuw i8, ptr (' + SSA + '), i64 (' + SSA + ')', copying[0])
    lanes, position = source_gep.groups()
    pointer_at(function, lanes, 656)
    commit, error = conditional(blocks[copy_result], copied, 4 if old else -1)
    committed = blocks[commit]
    require(len(committed) == 3, 'closed position commit block')
    store = match('store i64 (' + SSA + '), ptr (' + SSA + '), align 8', committed[0])
    end, cursor = store.groups()
    pointer_at(function, cursor, 616)
    empty = match('(' + SSA + ') = icmp eq i64 (' + SSA + '), 0', committed[1])
    depleted, next_length = empty.groups()
    final, loop = match('br i1 ' + re.escape(depleted) + ', label %(' + LABEL + '), label %(' + LABEL + ')', committed[2]).groups()
    loop_body = blocks[loop]
    require(len(loop_body) == 6, 'closed cursor/destination/length loop')
    phi = match('(' + SSA + ') = phi i64 \\[ (' + SSA + '), %(' + LABEL + ') \\], \\[ '
                + re.escape(end) + ', %' + re.escape(commit) + r' \]', loop_body[0])
    current, initial_position, preheader = phi.groups()
    destination_phi = match(re.escape(target) + r' = phi ptr \[ ' + re.escape(destination) + ', %'
                            + re.escape(preheader) + r' \], \[ (' + SSA + '), %' + re.escape(commit) + r' \]', loop_body[1])
    next_destination = destination_phi[1]
    remaining = match('(' + SSA + r') = phi i64 \[ ' + re.escape(length) + ', %' + re.escape(preheader)
                      + r' \], \[ ' + re.escape(next_length) + ', %' + re.escape(commit) + r' \]', loop_body[2])[1]
    rate, rate_pointer = match('(' + SSA + ') = load i64, ptr (' + SSA + '), align 32', loop_body[3]).groups()
    pointer_at(function, rate_pointer, 608)
    boundary = match('(' + SSA + ') = icmp eq i64 ' + re.escape(current) + ', ' + re.escape(rate), loop_body[4])[1]
    permute_label, available = match('br i1 ' + re.escape(boundary) + ', label %(' + LABEL + '), label %(' + LABEL + ')', loop_body[5]).groups()
    initial = blocks[preheader]
    require(len(initial) == 5, 'closed loop initialization')
    for line, name, offset in zip(initial[:3], (cursor, rate_pointer, lanes), (616, 608, 656)):
        match(re.escape(name) + r' = getelementptr inbounds nuw i8, ptr %self, i64 ' + str(offset), line)
    match(re.escape(initial_position) + ' = load i64, ptr ' + re.escape(cursor) + ', align 8', initial[3])
    match('br label %' + re.escape(loop), initial[4])
    permute, permuting, args, permuted, (permute_result, permute_unwind) = calls['permute']
    require(permute == permute_label and len(permuting) == 2 and len(args) == 2
            and [comparison.pointer(arg) for arg in args] == ['%self', lanes]
            and permute_unwind == unwind, 'permutation receives same session/state and unwind guard')
    reset, permute_error = conditional(blocks[permute_result], permuted, 7 if old else -1)
    require(permute_error == error, 'permutation failure reaches terminal cleanup')
    reset_body = blocks[reset]
    require(len(reset_body) == 3, 'closed permutation cursor reset')
    match('store i64 0, ptr ' + re.escape(cursor) + ', align 8', reset_body[0])
    refreshed = match('(' + SSA + ') = load i64, ptr ' + re.escape(rate_pointer) + ', align 32', reset_body[1])[1]
    match('br label %' + re.escape(available), reset_body[2])
    availability = blocks[available]
    require(len(availability) == (4 if old else 8), 'closed nonempty rate remainder check')
    match(re.escape(position) + r' = phi i64 \[ ' + re.escape(current) + ', %' + re.escape(loop)
          + r' \], \[ 0, %' + re.escape(reset) + r' \]', availability[0])
    active_rate = match('(' + SSA + r') = phi i64 \[ ' + re.escape(rate) + ', %' + re.escape(loop)
                        + r' \], \[ ' + re.escape(refreshed) + ', %' + re.escape(reset) + r' \]', availability[1])[1]
    if old:
        nonempty = match('(' + SSA + ') = icmp ugt i64 ' + re.escape(active_rate) + ', ' + re.escape(position), availability[2])[1]
    else:
        valid = match('(' + SSA + ') = icmp uge i64 ' + re.escape(active_rate) + ', ' + re.escape(position), availability[2])[1]
        raw = match('(' + SSA + ') = sub nuw i64 ' + re.escape(active_rate) + ', ' + re.escape(position), availability[3])[1]
        difference = match('(' + SSA + ') = select i1 ' + re.escape(valid) + ', i64 ' + re.escape(raw) + ', i64 undef', availability[4])[1]
        positive = match('(' + SSA + ') = icmp ne i64 ' + re.escape(difference) + ', 0', availability[5])[1]
        nonempty = match('(' + SSA + ') = select i1 ' + re.escape(valid) + ', i1 ' + re.escape(positive) + ', i1 false', availability[6])[1]
    arithmetic = match('br i1 ' + re.escape(nonempty) + ', label %(' + LABEL + '), label %' + re.escape(error), availability[-1])[1]
    addition = blocks[arithmetic]
    require(len(addition) == (6 if old else 4), 'closed count/end arithmetic')
    if old:
        difference = match('(' + SSA + ') = sub nuw i64 ' + re.escape(active_rate) + ', ' + re.escape(position), addition[0])[1]
    minimum = addition[1 if old else 0]
    match(re.escape(count) + r' = tail call noundef i64 @llvm.umin.i64\(i64 ' + re.escape(remaining) + ', i64 ' + re.escape(difference) + r'\)', minimum)
    if old:
        sum_pair = match('(' + SSA + r') = tail call \{ i64, i1 \} @llvm.uadd.with.overflow.i64\(i64 '
                         + re.escape(position) + ', i64 ' + re.escape(count) + r'\)', addition[2])[1]
        overflow = match('(' + SSA + r') = extractvalue \{ i64, i1 \} ' + re.escape(sum_pair) + ', 1', addition[3])[1]
        match(re.escape(end) + ' = add nuw i64 ' + re.escape(count) + ', ' + re.escape(position), addition[4])
    else:
        match(re.escape(end) + ' = add i64 ' + re.escape(count) + ', ' + re.escape(position), addition[1])
        overflow = match('(' + SSA + ') = icmp ult i64 ' + re.escape(end) + ', ' + re.escape(position), addition[2])[1]
    capacity = match('br i1 ' + re.escape(overflow) + ', label %' + re.escape(error) + ', label %(' + LABEL + ')', addition[-1])[1]
    bounded = blocks[capacity]
    require(len(bounded) == 4, 'closed source range/end check')
    match(re.escape(next_destination) + ' = getelementptr inbounds nuw i8, ptr ' + re.escape(target) + ', i64 ' + re.escape(count), bounded[0])
    match(re.escape(next_length) + r' = sub nuw(?: nsw)? i64 ' + re.escape(remaining) + ', ' + re.escape(count), bounded[1])
    check = match('(' + SSA + ') = icmp ' + ('ugt' if old else 'ult') + ' i64 ' + re.escape(end) + ', ' + ('200' if old else '201'), bounded[2])[1]
    yes, no = (error, copy_label) if old else (copy_label, error)
    match('br i1 ' + re.escape(check) + ', label %' + re.escape(yes) + ', label %' + re.escape(no), bounded[3])
    cleanup(function, blocks, error, copy_result, permute_result, permuted, names['wipe'], unwind, final, old)


def cleanup(function, blocks, error, copy_result, permute_result, permuted, wipe, unwind, final, old):
    body = blocks[error]
    require(len(body) == 7, 'closed error cleanup block')
    result = match('(' + SSA + ') = phi i8 (.+)', body[0])
    entries = re.findall(r'\[ ([^,]+), %(' + LABEL + r') \]', result[2])
    require(len({pred for _, pred in entries}) == len(entries)
            and ', '.join(f'[ {value}, %{pred} ]' for value, pred in entries) == result[2]
            and dict((pred, value) for value, pred in entries).get(copy_result) == '10'
            and dict((pred, value) for value, pred in entries).get(permute_result) == permuted, 'copy/permutation errors retained')
    terminal = match('store i8 1, ptr (' + SSA + '), align 1', body[1])[1]
    pointer_at(function, terminal, 859)
    cursor = match('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %self, i64 616', body[2])[1]
    match('store i64 0, ptr ' + re.escape(cursor) + ', align 8', body[3])
    memory = match('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %self, i64 624', body[4])[1]
    name, args = shared.invocation(body[5])
    require(name == wipe and len(args) == 1 and comparison.pointer(args[0]) == memory, 'original engine memory wipe request')
    output = match('br label %(' + LABEL + ')', body[6])[1]
    returned = blocks[output]
    require(len(returned) == 2, 'closed return result')
    value = match('(' + SSA + r') = phi i8 \[ ' + re.escape(result[1]) + ', %' + re.escape(error)
                  + r' \], \[ ' + ('12' if old else '-1') + ', %' + re.escape(final) + r' \]', returned[0])[1]
    match('ret i8 ' + re.escape(value), returned[1])
    landing = blocks[unwind]
    require(len(landing) == 3 and landing[1] == 'cleanup'
            and re.fullmatch(SSA + r' = landingpad \{ ptr, i32 \}', landing[0]), 'recoverable unwind landing')
    guarded = blocks[match('br label %(' + LABEL + ')', landing[2])[1]]
    require(len(guarded) == 7, 'closed unwind engine cleanup')
    exception = match('(' + SSA + r') = phi \{ ptr, i32 \} (.+)', guarded[0])
    incoming = re.findall(r'\[ (' + SSA + '), %(' + LABEL + r') \]', exception[2])
    landing_value = match('(' + SSA + r') = landingpad \{ ptr, i32 \}', landing[0])[1]
    require(len(incoming) == 2 and len({pred for _, pred in incoming}) == 2
            and ', '.join(f'[ {value}, %{pred} ]' for value, pred in incoming) == exception[2]
            and (landing_value, unwind) in incoming, 'original operation exception forwarded')
    match('store i8 1, ptr ' + re.escape(terminal) + ', align 1', guarded[1])
    cursor = match('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %self, i64 616', guarded[2])[1]
    match('store i64 0, ptr ' + re.escape(cursor) + ', align 8', guarded[3])
    memory = match('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %self, i64 624', guarded[4])[1]
    name, args = shared.invocation(guarded[5])
    require(name == wipe and len(args) == 1 and comparison.pointer(args[0]) == memory, 'unwind original memory wipe')
    resume, terminate = shared.edges(guarded[6])
    require(blocks[resume] == ['resume { ptr, i32 } ' + exception[1]], 'cleanup resumes original unwind')
    require(blocks[terminate][-1] == 'unreachable'
            and any('16panic_in_cleanup' in line for line in blocks[terminate]), 'double panic is nonreturning')


def cases(record):
    document = json.loads(record.read_text())
    comparison.validate_record(document, record.parent)
    for row in document['records']:
        if row['profile'] != 'release' or row['mode'] != 'accelerated':
            continue
        def artifact(package):
            return next((record.parent / path).read_text() for path in row['artifacts']
                        if Path(path).name.startswith(package + '-') and path.endswith('.ll'))
        yield *(artifact(package) for package in ('brynja_hash_sha3', 'brynja_core', 'brynja_crypto_cpu')), row['compiler'].splitlines()[0].split()[1]


def main(record):
    before = comparison.capture.sources()
    count = 0
    for case in cases(record):
        inspect(*case)
        count += 1
    require(count == 4 and before == comparison.capture.sources(), 'complete unchanged read matrix')
    print('Accelerated read: four optimized loop/copy/error/unwind boundaries PASS')
    print('Original destination, bounded state slices, checked cursor progress and terminal cleanup requests preserved')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not preflight/output-counter proof, callee implementation, debug, full spills or native-platform qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
