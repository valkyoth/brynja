#!/usr/bin/env python3
"""Retained accelerated debug read body composed with bulk/consuming readers."""
import argparse
from pathlib import Path

from debug_composed_read_model import ComposedRead, read, preflight, bridges, model, require

comparison, operation = read.comparison, preflight.operation
CLEANUP = [('state', 859, 1, 1), ('state', 616, 8, 0)] + [
    ('wipe', 'storage', offset, size) for offset, size in
    ((656, 200), (624, 16), (640, 16), (856, 2), (864, 168), (1056, 2))]


def closure(case, consuming):
    root, producer, names, _, merged = preflight.closure(case, consuming)
    read_names, selected, _ = read.closure(case)
    for key in names.keys() & read_names.keys() - {'panics'}:
        require(names[key] == read_names[key], 'same original engine/outer role: ' + key)
    names.update(read_names)
    for name, body in selected.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical composed helper')
        merged[name] = body
    return root, producer, names, merged


def expected(length, consuming, valid, counter, rate, position, failed, squeezing,
             session_fault, read_fault, failure, names):
    mode = int(consuming)
    session_calls, chunks, records = 0, 0, []
    effective = failure
    preliminary, _, _ = operation.expected(length, mode, valid, failure)
    for event in preliminary:
        if event == ('preflight',):
            session_calls += int(not failed and squeezing)
            session = session_fault[1] if session_fault and session_fault[0] == session_calls else names['session_success']
            error, state, reads = preflight.expected(counter, length, failed, squeezing, session, names['session_success'])
            records.append(('engine-preflight', tuple(state), tuple(reads), (counter,) if reads else ()))
            if error is not None:
                effective = ('preflight', 0, error)
                break
        elif event[0] == 'read':
            chunks += 1
            chunk = event[1]
            session_calls += int(not failed and squeezing)
            session = session_fault[1] if session_fault and session_fault[0] == session_calls else names['session_success']
            fault = read_fault[1] if read_fault and read_fault[0] == chunks else None
            trace, error, state, copied, reads = read.expected(chunk, counter, rate, position, failed,
                                                              squeezing, session, fault, names['session_success'])
            records.append(('engine-read', tuple(trace), tuple(state), tuple(reads), copied,
                            (0, 1) if error is None else (0,)))
            if error is not None:
                effective = ('read', chunks, error)
                break
            counter += chunk
            position = [item[1] for item in trace if item[0] == 'position'][-1]
    inner, progress, success = operation.expected(length, mode, valid, effective)
    events, pending = [('producer-enter',)], iter(records)
    for event in inner:
        events.append(event)
        if event[0] in ('preflight', 'read'):
            events.append(next(pending))
    require(next(pending, None) is None, 'oracle accounts for every expected engine call')
    events += [('producer-exit',)] + (CLEANUP if consuming else [])
    unwound = effective is not None and effective[2] == 'unwind'
    if not unwound:
        if success:
            fields = ((8, 8, model.Pointer('output')), (16, 8, length), (0, 8, 1)) if length else ((0, 8, 0),)
            events += [('outer-descriptor',)] + [('result', *field) for field in fields] + [('outer-descriptor',)]
        else:
            errors = [item[3] for item in inner if item[:3] == ('result', 8, 1)]
            require(len(errors) == 1, 'one oracle producer error')
            events += [('result', 8, 1, errors[0]), ('result', 0, 8, 2)]
    return events, progress, success, unwound, counter, position, session_calls, chunks


def scenarios(thorough, consuming):
    lengths = (0, 1, 135, 136, 167, 168, 169, 336, 337, 505) if thorough else (0, 169, 337)
    for rate in (72, 104, 136, 144, 168) if thorough else (136,):
        for length in lengths:
            for position in (0, rate - 1, rate) if thorough else (rate,):
                for counter in (0, preflight.MAXIMUM - length, preflight.MAXIMUM) if thorough else (0,):
                    yield length, 7 if length else 0, counter, rate, position, 0, 1, None, None, None
    for failed, squeezing in ((0, 0), (1, 0), (1, 1)):
        yield 337, 7, 3, 136, 136, failed, squeezing, None, None, None
    for call in (1, 2, 3, 4):
        for error in (*range(7), 'unwind') if thorough else (3, 'unwind'):
            yield 337, 7, 3, 136, 136, 0, 1, (call, error), None, None
    for chunk in (1, 2, 3):
        for role, values in (('permute', (*range(7), 'unwind')), ('copy', (*range(4), 'unwind')), ('writer', ('unwind',))):
            for error in values if thorough else ('unwind',):
                yield 505, 7, 3, 72, 72, 0, 1, None, (chunk, (role, 0 if role == 'writer' else 1, error)), None
    for failure in (('clear', 0, 2), ('copy', 2, 'unwind'), ('write', 2, 2), ('slice', 2, None),
                    ('take', 0, 'unwind'), ('predicate', 0, 'unwind')):
        yield 337, 7, 3, 136, 136, 0, 1, None, None, failure
    if consuming:
        for valid in (0, 1, 8, 9, 255):
            yield 337, valid, 3, 136, 136, 0, 1, None, None, None
        yield 337, 7, 3, 136, 136, 0, 1, None, None, ('mask', 3, 'unwind')


def inspect(case, thorough=True, consuming=True):
    root, producer, names, merged = closure(case, consuming)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in merged.items()}
    constants = '\n'.join(dict.fromkeys(line for text in (case.sha3, case.core, case.hash_core, case.kmac)
                                      for line in text.splitlines() if line.startswith(('@anon.', '@alloc_'))))
    count, visited = 0, set()
    for scenario in scenarios(thorough, consuming):
        length, valid, counter, rate, position, failed, squeezing, session_fault, read_fault, failure = scenario
        valid = valid if consuming else model.UNKNOWN
        machine = ComposedRead(functions, constants, names, length, int(consuming), valid, producer,
                               counter, rate, position, failed, squeezing, session_fault, read_fault, failure)
        result = machine.allocate('result', 24)
        reader = machine.allocate('entry-reader', 8)
        storage = machine.allocate('storage', 1088, payload=True)
        output = machine.allocate('output', length, payload=True)
        machine.fields(reader, [(0, 8, storage)])
        machine.events.clear()
        unwound = False
        try:
            require(machine.run(root, [result, reader, output, length] + ([valid] if consuming else [])) is None,
                    'void actual composed reader')
        except model.Unwind as error:
            require(error.value == machine.exception, 'original engine exception through both outer guards')
            unwound = True
        events, progress, success, unwind, counter_end, cursor_end, sessions, chunks = expected(
            length, consuming, valid, counter, rate, position, failed, squeezing, session_fault, read_fault, failure, names)
        require(machine.events == events, 'exact composed read/outer trace: ' + repr((consuming, scenario)) + '; difference=' + repr(next(
            ((i, a, b) for i, (a, b) in enumerate(zip(machine.events, events)) if a != b),
            ('lengths', len(machine.events), len(events)))))
        require(machine.progress == progress and unwound == unwind and machine.read_calls == chunks
                and machine.session_calls == sessions and machine.preflight_calls == chunks + int(('preflight',) in events)
                and machine.producer_calls == 1 and not any((machine.in_read, machine.in_preflight, machine.in_guard,
                    machine.in_producer, machine.inside_operation, machine.writing, machine.decoding))
                and machine.guard_stores == ([] if failure and failure[0] == 'clear' else [0, 1] if success else [0]),
                'exact nested calls, original exception and success-only outer completion')
        require(machine.load(reader, 8) == storage and machine.load(machine.reader_address, 8) == storage,
                'both reader aliases still bind original engine')
        if success and not consuming:
            require(int.from_bytes(machine.counter_bytes, 'little') == counter_end and machine.position == cursor_end
                    and not machine.failed, 'successful bulk read preserves exact reusable engine metadata')
        else:
            require(machine.failed == 1 and machine.position == 0, 'failed or consumed owner is terminal')
        visited.update(machine.visited)
        count += 1
    return count, merged, visited


def main(record, shard, quick):
    before = comparison.capture.sources()
    cases = list(operation.cases(record))
    require(len(cases) == 8, 'eight retained debug accelerated paths')
    for case in cases if shard is None else [cases[shard]]:
        for consuming in (False, True):
            count, merged, _ = inspect(case, not quick, consuming)
            print(f'Composed engine read {consuming=}: {count} cases; {len(merged)} functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all eight paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Primitive bodies opaque; synthetic unwind only; F1/whole-call qualification remain open')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    parser.add_argument('--quick', action='store_true')
    args = parser.parse_args()
    main(args.record.resolve(), args.shard, args.quick)
