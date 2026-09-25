#!/usr/bin/env python3
"""Retained engine-read body, preflight/counters and its own cleanup guard."""
import argparse
import json
from pathlib import Path
import re

from debug_accelerated_read_model import ReadModel, preflight, model, require

comparison = preflight.comparison
CLEANUP = [('failed',), ('position', 0)] + [('wipe', offset, length)
           for offset, length in ((656, 200), (624, 16), (640, 16), (856, 2))]


def closure(case):
    _, _, names, _, merged = preflight.closure(case, False)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core', 'hash_core')}
    read = artifacts['sha3'][names['read']]
    for role, token in (('split', '12split_at_mut'), ('writer', 'engine11write_count'),
                        ('end_add', '11checked_add'), ('subtract', '11checked_sub'), ('lane_get', '3get')):
        calls = [name for name in preflight.bridges.bulk.calls(read) if token in name
                 and (role != 'end_add' or 'usize' in name or '3numj' in name)]
        require(len(calls) == 1, 'unique actual read helper: ' + role)
        names[role] = calls[0]
    pending, selected, panics, boundaries = [(names['read'], 'sha3')], {}, set(), {}
    while pending:
        name, source = pending.pop()
        if name.startswith('llvm.'):
            require(name in ('llvm.memcpy.p0.p0.i64', 'llvm.uadd.with.overflow.i64',
                             'llvm.uadd.with.overflow.i128', 'llvm.umul.with.overflow.i64'), 'known read intrinsic')
            continue
        if 'panicking' in name:
            panics.add(name)
            continue
        if '13KeccakSession' in name:
            role = 'permutation' if '7permute' in name else 'session'
            declarations = [line for line in case.sha3.splitlines() if line.startswith('declare i8 @') and name + '(' in line]
            require(len(declarations) == 1 and not re.search(r'\b(?:byval|inalloca)\b', declarations[0]), 'borrowed CPU boundary')
            args = comparison.arguments(declarations[0], re.search(comparison.SYMBOL, declarations[0]).end())
            require(len(args) == (2 if role == 'permutation' else 1) and all(arg == 'ptr' or arg.startswith('ptr ') for arg in args),
                    'original CPU session/lane pointer ABI')
            boundaries[role] = name
            continue
        if name not in artifacts[source]:
            sources = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(sources) == 1, 'unambiguous same-row engine-read helper: ' + name)
            source = sources[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed engine-read/helper ABI')
        if name in (names['split'], names['wipe']) or '18copy_secret_region' in name:
            role = 'split' if name == names['split'] else 'wipe' if name == names['wipe'] else 'lane_copy'
            header = body.splitlines()[0]
            args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
            types = {'split': ('ptr', 'ptr', 'i64', 'i64', 'ptr'), 'wipe': ('ptr', 'i64'),
                     'lane_copy': ('ptr', 'i64', 'ptr', 'i64')}[role]
            require(len(args) == len(types) and all(arg.startswith(kind + ' ') for arg, kind in zip(args, types)),
                    'defined original primitive ABI: ' + role)
            if role == 'split':
                require(args[0].startswith('ptr sret([32 x i8])'), 'complete split descriptor')
            boundaries[role] = name
            continue
        if name in selected:
            require(model.parameters(body) == model.parameters(selected[name]) and model.blocks(body) == model.blocks(selected[name]),
                    'identical shared read helper')
            continue
        selected[name] = body
        pending.extend((callee, source) for callee in preflight.bridges.bulk.calls(body))
    require(set(boundaries) == {'session', 'permutation', 'split', 'wipe', 'lane_copy'}, 'five explicit read boundaries')
    require(boundaries['session'] == names['session'], 'same preflight session boundary')
    names.update(boundaries, panics=panics, copy_success=4 if case.compiler == '1.90.0' else 255)
    for name, body in selected.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'same engine/preflight helper')
        merged[name] = body
    return names, selected, merged


def expected(length, counter, rate, position, failed, squeezing, session, fault, session_success):
    error, state, reads = preflight.expected(counter, length, failed, squeezing, session, session_success)
    trace = [('decode', counter)] if reads else []
    if reads:
        state = state[:-1]  # Decoder is recorded in the engine trace, not twice.
    if error is not None:
        return trace + CLEANUP, error, state, 0, reads
    value = preflight.MAXIMUM if fault == ('counter', 2, 'overflow') else counter
    trace.append(('decode', value))
    reads += list(range(16))
    if value + length > preflight.MAXIMUM:
        return trace + CLEANUP, 8, state, 0, reads
    copied = permutations = copies = 0
    while copied < length:
        if position == rate:
            trace.append(('permute',))
            permutations += 1
            if fault and fault[:2] == ('permute', permutations):
                return trace + CLEANUP, fault[2], state, copied, reads
            position = 0
            trace.append(('position', 0))
        if fault == ('subtract', 0, 'none'):
            return trace + [('missing', 'subtract')] + CLEANUP, 7, state, copied, reads
        if position >= rate:
            return trace + CLEANUP, 7, state, copied, reads
        count = min(rate - position, length - copied)
        if fault == ('end_add', 0, 'none'):
            return trace + [('missing', 'end_add')] + CLEANUP, 8, state, copied, reads
        if fault == ('lane_get', 0, 'none'):
            return trace + [('missing', 'lane_get')] + CLEANUP, 7, state, copied, reads
        if position + count > 200:
            return trace + CLEANUP, 7, state, copied, reads
        trace.append(('copy', copied, position, count))
        copies += 1
        if fault and fault[:2] == ('copy', copies):
            return trace + CLEANUP, 'unwind' if fault[2] == 'unwind' else 10, state, copied, reads
        copied += count
        position += count
        trace.append(('position', position))
    trace.append(('write-counter', value + length))
    if fault == ('writer', 0, 'unwind'):
        return trace + CLEANUP, 'unwind', state, copied, reads
    trace += [('byte', index, byte) for index, byte in enumerate((value + length).to_bytes(16, 'little'))]
    return trace, None, state, copied, reads


def scenarios(thorough, success):
    for counter in preflight.decode.values(thorough):
        yield 0, counter, 168, 0, 0, 1, success, None
    rates = (72, 104, 136, 144, 168) if thorough else (136, 168)
    for rate in rates:
        for position in (0, 1, rate - 1, rate):
            lengths = (0, 1, rate - 1, rate, rate + 1, 2 * rate + 1) if thorough else (0, 1, rate + 1)
            for length in lengths:
                for counter in (0, preflight.MAXIMUM - length, preflight.MAXIMUM):
                    yield length, counter, rate, position, 0, 1, success, None
    for failed, squeezing in ((0, 0), (1, 0), (1, 1), (0, 1)):
        for session in (*range(7), success, 'unwind'):
            yield 169, 7, 168, 0, failed, squeezing, session, None
    # Corrupt metadata/helper results are internal invariant probes, not valid
    # public constructors or evidence of exploitable reachable states.
    for rate, position in ((0, 0), (136, 137), (201, 200), (model.MASK, model.MASK - 1)):
        yield 3, 7, rate, position, 0, 1, success, None
    for role in ('subtract', 'end_add', 'lane_get'):
        yield 3, 7, 168, 0, 0, 1, success, (role, 0, 'none')
    yield 1, 7, 168, 0, 0, 1, success, ('counter', 2, 'overflow')
    for boundary in (0, 1, 337):
        yield boundary, 7, 168, 0, 0, 1, success, ('writer', 0, 'unwind')
    for iteration in (1, 2, 3):
        for error in (*range(7), 'unwind'):
            yield 337, 7, 168, 168, 0, 1, success, ('permute', iteration, error)
        for error in (*range(4), 'unwind'):
            yield 337, 7, 168, 0, 0, 1, success, ('copy', iteration, error)


def inspect(case, thorough=True):
    names, selected, merged = closure(case)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in merged.items()}
    constants = '\n'.join(dict.fromkeys(line for text in (case.sha3, case.core, case.hash_core, case.kmac)
                                      for line in text.splitlines() if line.startswith(('@anon.', '@alloc_'))))
    count, visited = 0, set()
    for length, counter, rate, position, failed, squeezing, session, fault in scenarios(thorough, names['session_success']):
        machine = ReadModel(functions, constants, names, length, counter, rate, position, failed, squeezing, session, fault)
        storage = machine.allocate('storage', 1088, payload=True)
        destination = machine.allocate('output', length, payload=True)
        unwound, result = False, None
        try:
            result = machine.run(names['read'], [storage, destination, length])
        except model.Unwind as error:
            require(error.value == machine.exception, 'original exception after engine cleanup')
            unwound = True
        trace, error, state, copied, reads = expected(length, counter, rate, position, failed, squeezing,
                                                    session, fault, names['session_success'])
        require(machine.read_trace == trace, 'exact engine read/commit/cleanup trace: '
                + repr((length, counter, rate, position, failed, squeezing, session, fault)) + '; difference=' + repr(next(
                    ((i, a, b) for i, (a, b) in enumerate(zip(machine.read_trace, trace)) if a != b),
                    ('lengths', len(machine.read_trace), len(trace)))))
        require(machine.events == [('preflight',)] and machine.engine_events == state and machine.reads == reads
                and machine.copied == copied and machine.preflight_calls == 1 and not machine.in_read and not machine.writing
                and machine.engine_guard_stores == ([0, 1] if error is None else [0])
                and unwound == (error == 'unwind') and (unwound or result == (names['success'] if error is None else error)),
                'read result/guard/state/counter/exception match independent oracle')
        if error is None:
            require(int.from_bytes(machine.counter_bytes, 'little') == counter + length and not machine.failed,
                    'only complete successful reads commit output count')
        else:
            require(machine.failed == 1 and machine.position == 0, 'engine error/unwind irreversibly terminal')
        count += 1
        visited.update(machine.visited)
    for label, lines in model.blocks(selected[names['read']]).items():
        if lines == ['unreachable'] or any('16panic_in_cleanup' in line for line in lines):
            continue
        require((names['read'], label) in visited, 'all nonpanic engine-read body blocks exercised')
    return count, selected, merged, visited


def main(record, shard):
    before = comparison.capture.sources()
    cases = list(preflight.operation.cases(record))
    require(len(cases) == 8, 'eight retained accelerated debug paths')
    for case in cases if shard is None else [cases[shard]]:
        count, selected, merged, _ = inspect(case)
        print(f'Accelerated engine read: {count} cases; {len(selected)} read/{len(merged)} total functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all 8 paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Session/permutation/split/copy/volatile boundaries opaque; outer read integration/whole-call qualification pending')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
