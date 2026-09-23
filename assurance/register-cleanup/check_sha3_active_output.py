#!/usr/bin/env python3
"""Retained active-reader initialization transfer and squeeze argument routing."""
import argparse
import json
from pathlib import Path
import re

import check_sha3_terminal_output as terminal

adapter = terminal.adapter
comparison = terminal.comparison
require = terminal.require
SSA = terminal.SSA


def clean(lines):
    return [line for line in lines if not re.fullmatch(r'call void @llvm.experimental.noalias.scope.decl\(metadata !\d+\)', line)]


def inspect(function, begin, wipes, drop, callees):
    trace, (_, merge, _, _, _), (_, _, original) = terminal.inspect(function, begin, wipes, drop)
    graph = trace.graph
    _, _, origin = adapter.routes.transfer.finish.graph_info(function)

    def assigned(line, pattern, label):
        match = re.fullmatch('(' + SSA + ') = ' + pattern, line)
        require(match is not None, label)
        return match[1]

    def gep(line, base, offset):
        return assigned(line, r'getelementptr inbounds nuw i8, ptr ' + re.escape(base) + ', i64 ' + str(offset), 'original operation field address')

    def load(line, kind, address, align=8):
        return assigned(line, 'load ' + kind + ', ptr ' + re.escape(address) + ', align ' + str(align), 'read original operation metadata')

    # Bind the public length/final-bit metadata referenced by the transferred
    # operation descriptor; preceding checks already confine these stores.
    cast = [assigned(line, r'zext i1 %0 to i8', 'original final-mode flag')
            for line in graph['start'] if ' = zext i1 ' in line]
    require(len(cast) == 1, 'one final-mode conversion')
    stores = []
    for line in graph['start']:
        match = re.fullmatch(r'store (i8|i64) (' + SSA + r'), ptr (' + SSA + r'), align (1|4|8)', line)
        if match:
            stores.append((match[1], match[2], origin(match[3])))
    require(stores == [('i8', cast[0], ('%valid', 0)), ('i8', '%1', ('%valid', 1)),
                       ('i64', '%destination.1', ('%length', 0))], 'unchanged input mode/valid/length metadata')
    _, active, _ = adapter.shape.branch(trace, merge)
    lines = clean(graph[active])
    require(len(lines) == 7, 'closed active-reader descriptor handoff')
    flag = re.fullmatch(r'store i8 0, ptr (' + SSA + '), align 8', lines[0])
    require(flag is not None and origin(flag[1]) == ('%self', 8), 'reader becomes inactive before operation')
    owner = load(lines[1], 'ptr', '%self')
    name, args = adapter.routes.guard.call(lines[2])
    work = comparison.pointer(args[-1])
    require(name == 'llvm.lifetime.start.p0' and args in
            (['ptr nonnull ' + work], ['i64 48', 'ptr nonnull ' + work])
            and work + ' = alloca [48 x i8], align 8' in graph['start'] and work != original,
            'distinct bounded live operation descriptor')
    name, args = adapter.routes.guard.call(lines[3])
    require(lines[3].startswith('call void @') and name == 'llvm.memcpy.p0.p0.i64' and len(args) == 4
            and comparison.pointer(args[0]) == work and comparison.pointer(args[1]) == original
            and args[2:] == ['i64 48', 'i1 false'], 'complete unchanged operation descriptor transfer')
    present = load(lines[4], 'i64', work)
    tested = assigned(lines[5], r'trunc nuw i64 ' + re.escape(present) + ' to i1', 'original output ownership discriminator')
    condition, choose, empty = adapter.shape.branch(trace, active)
    require(condition == tested and choose != empty, 'only owned nonempty output reaches squeezing')
    selection = graph[choose]
    require(len(selection) == 6, 'closed bulk/final selection')
    output = gep(selection[0], work, 8)
    mode_field = gep(selection[1], work, 32)
    mode = load(selection[2], 'ptr', mode_field)
    value = load(selection[3], 'i8', mode, 1)
    tested = assigned(selection[4], r'trunc nuw i8 ' + re.escape(value) + ' to i1', 'original final-bit presence flag')
    condition, final, bulk = adapter.shape.branch(trace, choose)
    require(condition == tested and final != bulk, 'correct final/bulk routing')
    routes = []
    for label, is_final in ((final, True), (bulk, False)):
        block = graph[label]
        require(len(block) == (7 if is_final else 5), 'closed squeeze argument setup')
        index = 0
        if is_final:
            valid_field = gep(block[0], mode, 1)
            valid = load(block[1], 'i8', valid_field, 1)
            index = 2
        length_field = gep(block[index], work, 40)
        length_pointer = load(block[index + 1], 'ptr', length_field)
        length = load(block[index + 2], 'i64', length_pointer)
        call = block[index + 3]
        result = re.match('(' + SSA + r') = invoke fastcc noundef i8 @', call)
        name, args = adapter.routes.guard.call(call)
        token = '25squeeze_final_bits_secret' if is_final else '14squeeze_secret'
        require(result is not None and name in callees and token in name and len(args) == (4 if is_final else 3),
                'defined matching portable squeeze operation and ABI')
        require(comparison.pointer(args[0]) == owner, 'squeeze receives original borrowed owner')
        if is_final:
            require(args[1:3] == ['i64 noundef ' + length, 'i8 noundef ' + valid]
                    and comparison.pointer(args[3]) == output, 'original final length/bits and initialization handle')
        else:
            require(comparison.pointer(args[1]) == output and args[2] == 'i64 noundef ' + length,
                    'original bulk initialization handle and length')
        decision, unwind = trace.edges[label][0]
        routes.append((label, name, decision, unwind, result[1]))
    require(routes[0][3] == routes[1][3], 'both squeeze calls have a shared exceptional cleanup edge')
    require(set(label for label in graph if active in trace.edges[label][0]) == {merge}
            and set(label for label in graph if choose in trace.edges[label][0]) == {active}
            and all(set(parent for parent in graph if label in trace.edges[parent][0]) == {choose}
                    for label in (final, bulk)), 'no alternate entry bypasses ownership handoff')
    return trace, (active, choose, final, bulk), routes, (work, output, owner)


def cases(record):
    definitions = {}
    for function, defined, wipes in terminal.entry.reader.cases(record):
        _, _, secret = terminal.entry.reader.inspect(function, defined, wipes)
        definitions[defined[secret]] = {
            name for name, body in defined.items() if 'hardened' in name and 'sponge' in name
            and 'HardenedFips202Owner' in name and 'accelerated' not in name
            and ('14squeeze_secret' in name or '25squeeze_final_bits_secret' in name)
            and re.match(r'define internal fastcc noundef(?: range\(i8 -?\d+, -?\d+\))? i8 @', body)}
    for function, begin, wipes, drop in terminal.cases(record):
        require(function in definitions, 'actual source-bound borrowed reader definition')
        yield function, begin, wipes, drop, definitions[function]


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*case) for case in cases(record)]
    require(len(checks) == 16 and before == comparison.capture.sources(), 'complete unchanged active-reader transfer matrix')
    print('Active reader handoff: 16 full descriptor transfers; 32 bound bulk/final squeeze calls receive original owner/output metadata PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Argument routing only; not squeeze callee semantics, result handling, unwind cleanup or register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
