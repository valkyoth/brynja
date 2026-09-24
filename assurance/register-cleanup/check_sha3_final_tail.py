#!/usr/bin/env python3
"""Retained final-bit length admission, low-bit masking and result routing."""
import argparse
import json
from pathlib import Path
import re
from types import SimpleNamespace

import check_read_counter as model
import check_secret_mask as masking
import check_sha3_squeeze_ownership as ownership

comparison = ownership.comparison
require = ownership.require
SSA = ownership.SSA
LABEL = r'(?:"[^"]+"|[-.$\w]+)'


def assigned(line, expression):
    match = re.fullmatch('(' + SSA + ') = ' + expression, line)
    require(match is not None, 'final-tail instruction: ' + line)
    return match[1]


def mask_bridge(function, primitive, arm):
    graph, _, _ = ownership.adapter.routes.transfer.finish.graph_info(function)
    header = function.splitlines()[0]
    params = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    require(len(params) == 3 and comparison.pointer(params[0]) == '%byte'
            and params[0].startswith('ptr noalias ') and 'dereferenceable(1)' in params[0]
            and params[1:] == ['i8 noundef %keep', 'i8 noundef %set'], 'one exclusive byte and original public masks')
    require(set(graph) == {'start'} and len(graph['start']) == 2
            and graph['start'][1] == 'ret void', 'closed mask forwarding body')
    call = graph['start'][0]
    name, args = ownership.adapter.routes.guard.call(call)
    require(call.startswith('tail call fastcc void @') and name == primitive
            and len(args) == 3 and comparison.pointer(args[0]) == '%byte'
            and args[1:] == [('i8 noundef ' if arm else 'i8 noundef zeroext ') + value for value in ('%keep', '%set')],
            'exact original byte and public mask forwarding')


def inspect(function, write, clear, bulk, compiler, fill, mask, *, thorough=True):
    graph, _, (writing, _, _, returning), final = ownership.inspect(function, write, clear, bulk, compiler)
    require(final, 'selected final-bit body')
    _, edges, _ = ownership.adapter.routes.transfer.finish.graph_info(function)
    trace = SimpleNamespace(graph=graph, edges=edges)
    branch = lambda label: ownership.adapter.shape.branch(trace, label)
    success = '5' if compiler == '1.90.0' else '-1'
    header = function.splitlines()[0]
    params = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    require(comparison.pointer(params[0]) == '%self' and params[1:3] == ['i64 noundef %output_bytes', 'i8 noundef %valid']
            and comparison.pointer(params[3]) == '%initialization', 'original final-bit metadata and borrows')
    start = graph['start']
    require(len(start) == 4, 'closed complete-byte switch')
    switch = re.fullmatch(r'switch i8 %valid, label %(' + LABEL + r') \[', start[0])
    zero = re.fullmatch(r'i8 0, label %(' + LABEL + ')', start[1])
    require(switch is not None and zero is not None and start[2] == 'i8 8, label %' + zero[1]
            and start[3] == ']', 'zero/full-byte modes share original length')
    partial, admission = switch[1], zero[1]
    require(len(graph[partial]) == 2, 'closed partial-byte length adjustment')
    shortened = assigned(graph[partial][0], r'tail call i64 @llvm.usub.sat.i64\(i64 %output_bytes, i64 1\)')
    require(graph[partial][1] == 'br label %' + admission, 'partial-byte adjustment enters admission')
    complete = assigned(graph[admission][0], r'phi i64 \[ ' + re.escape(shortened) + ', %' + re.escape(partial)
                        + r' \], \[ %output_bytes, %start \], \[ %output_bytes, %start \]')
    _, rejected, forwarding = branch(admission)
    require(rejected == returning, 'overflow rejects before any output work')
    lines = graph[forwarding]
    require(len(lines) == 3, 'closed full-byte forwarding')
    result = assigned(lines[0].split(' @', 1)[0], 'tail call fastcc noundef i8')
    name, args = ownership.adapter.routes.guard.call(lines[0])
    require(name == bulk and len(args) == 3 and comparison.pointer(args[0]) == '%self'
            and comparison.pointer(args[1]) == '%initialization' and args[2] == 'i64 noundef ' + complete,
            'bulk receives original owner, initializer and exact complete count')
    tested = assigned(lines[1], 'icmp eq i8 ' + re.escape(result) + ', ' + success)
    condition, choose_tail, failed = branch(forwarding)
    require(condition == tested and failed == returning, 'bulk error remains terminal')
    require(len(graph[choose_tail]) == 2, 'closed tail presence check')
    tested = assigned(graph[choose_tail][0], 'icmp eq i64 ' + re.escape(complete) + ', %output_bytes')
    condition, done, filling = branch(choose_tail)
    require(condition == tested and done == returning, 'only fractional output enters tail fill')
    lines = graph[filling]
    require(len(lines) == 3, 'closed one-byte fill')
    filled = assigned(lines[0].split(' @', 1)[0], 'tail call fastcc noundef i8')
    name, args = ownership.adapter.routes.guard.call(lines[0])
    require(name == fill and len(args) == 2 and comparison.pointer(args[0]) == '%self'
            and args[1] == 'i64 noundef 1', 'actual fill stages exactly one byte')
    tested = assigned(lines[1], 'icmp eq i8 ' + re.escape(filled) + ', ' + success)
    condition, ready, failed = branch(filling)
    require(condition == tested and ready == writing and failed == returning, 'mask/write only freshly filled tail')
    lines = graph[writing]
    stage = assigned(lines[0], r'getelementptr inbounds nuw i8, ptr %self, i64 584')
    shift = assigned(lines[1], r'tail call i8 @llvm.usub.sat.i8\(i8 8, i8 %valid\)')
    in_range = assigned(lines[2], 'icmp samesign ult i8 ' + re.escape(shift) + ', 8')
    shifted = assigned(lines[3], 'lshr i8 -1, ' + re.escape(shift))
    keep = assigned(lines[4], 'select i1 ' + re.escape(in_range) + ', i8 ' + re.escape(shifted) + ', i8 0')
    name, args = ownership.adapter.routes.guard.call(lines[5])
    require(lines[5].startswith('tail call void @') and name == mask and len(args) == 3
            and comparison.pointer(args[0]) == stage and args[1:] == ['i8 noundef ' + keep, 'i8 noundef 0'],
            'bound mask clears high bits without setting any bits before tail write')
    selected = re.match('(' + SSA + ') = select i1 ', lines[8 if compiler == '1.90.0' else 9])[1]
    phi = re.fullmatch('(' + SSA + r') = phi i8 (.+)', graph[returning][0])
    require(phi is not None, 'final result phi')
    entries = re.findall(r'\[ (' + SSA + r'|-?\d+), %(' + LABEL + r') \]', phi[2])
    require(len(entries) == 5 and ', '.join(f'[ {value}, %{parent} ]' for value, parent in entries) == phi[2]
            and {parent: value for value, parent in entries} ==
            {admission: '2', forwarding: result, choose_tail: success, filling: filled, writing: selected},
            'admission, bulk, fill and write results preserved')
    predecessors = {partial: {'start'}, admission: {'start', partial}, forwarding: {admission},
                    choose_tail: {forwarding}, filling: {choose_tail}, writing: {filling},
                    returning: {admission, forwarding, choose_tail, filling, writing}}
    require(set(graph) == {'start', *predecessors}, 'complete eight-block final-tail inventory')
    for label, expected in predecessors.items():
        require({parent for parent in graph if label in edges[parent][0]} == expected, 'no final-tail bypass')
    count = 0
    for valid in range(9):
        for length in ((0,) if valid == 0 else (1, 2, 136, 168, (1 << 64) - 1) if thorough else (1, 2)):
            whole = length if valid in (0, 8) else length - 1
            counters = {0, model.MAX, model.MAX - whole, 0x0102030405060708090a0b0c0d0e0f10}
            if whole:
                counters.add(model.MAX - whole + 1)
            for counter in counters:
                env = {'%output_bytes': length, '%valid': valid, shortened: max(length - 1, 0)}
                state = dict(counter=counter, writes=[])
                actual = model.evaluate(graph, admission, 'start' if valid in (0, 8) else partial,
                                        env, state, None, dict(error=returning, loop=forwarding), False, portable_bulk=True)
                require(not state['writes'], 'no counter write during final admission')
                if counter + whole > model.MAX:
                    require(actual == ('error', 2), 'final length overflow rejects before bulk')
                else:
                    require(actual[0] == 'loop' and actual[1][complete] == whole, 'admitted complete-byte count')
                count += 1
    return trace, (partial, admission, forwarding, choose_tail, filling, writing, returning), count


def cases(record):
    selected = {function: args for function, *args in ownership.cases(record)
                if '25squeeze_final_bits_secret' in function.splitlines()[0]}
    for row, _, core, assembly in comparison.cases(record):
        if row['profile'] != 'release':
            continue
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'same-row SHA-3 artifact')
        definitions = comparison.definitions(paths[0].read_text())
        core_defs = comparison.definitions(core)
        masks = [name for name in core_defs if '22apply_secret_byte_mask' in name]
        require(len(masks) == 1, 'defined core mask wrapper')
        bodies = [body for body in definitions.values() if body in selected]
        require(len(bodies) == 2, 'both reader-selected final-bit rates')
        for body in bodies:
            fills = [name for name in definitions if '12fill_staging' in name and '@' + name + '(' in body]
            require(len(fills) == 1, 'actual final-bit fill definition')
            yield (body, *selected[body], fills[0], masks[0]), core, assembly, row['target'].startswith('aarch64')


def dependency(core, assembly, arm):
    definitions = comparison.definitions(core)
    wrappers = [body for name, body in definitions.items() if '22apply_secret_byte_mask' in name]
    primitives = [name for name in definitions if 'secret_memory_mask9mask_byte' in name]
    require(len(wrappers) == len(primitives) == 1, 'unique actual mask dependency pair')
    mask_bridge(wrappers[0], primitives[0], arm)
    require(re.search(r'^' + re.escape(primitives[0]) + ':', assembly, re.M), 'matching mask assembly identity')
    masking.inspect(assembly, arm)


def main(record):
    before = comparison.capture.sources()
    results = []
    for case, core, assembly, arm in cases(record):
        results.append(inspect(*case)[2])
        dependency(core, assembly, arm)
    require(len(results) == 16 and before == comparison.capture.sources(), 'complete unchanged final-tail matrix')
    print(f'Final-bit tails: 16 bodies; {sum(results)} valid-metadata admission cases; exact low-bit mask and error routes PASS')
    print('Actual one-byte mask wrapper and matching cleanup assembly bound; existing write/staging cleanup checks composed')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Bounded/structural valid-input checks, not upstream metadata validation, all-input proof or whole-call/native qualification; Arm remains QEMU')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
