#!/usr/bin/env python3
"""Compose retained staging fill with the actual byte squeeze and owner guard."""
import argparse
import json
from pathlib import Path

import check_debug_staging_fill as fill

guard, model, require, comparison = fill.guard, fill.model, fill.require, fill.comparison


def closure(case):
    producer, _, _, _ = guard.operation.closure(case)
    outer_names, _, merged = guard.squeeze.closure(case)
    names, inner = fill.closure(case)
    for key, value in outer_names.items():
        require(key == 'panics' or names[key] == value, 'same staging/squeeze helper identities')
    names['panics'] |= outer_names['panics']
    for name, body in inner.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical shared fill/squeeze helper')
        merged[name] = body
    return producer, names, merged


class FilledSqueeze(fill.FillModel, guard.GuardedSqueeze):
    def __init__(self, functions, constants, names, previous, length, active, failure, clear_error, cursor, stage_fault):
        # Initialize the outer model directly. FillModel's handlers are reused
        # below, but its standalone constructor must not reset the guard state.
        guard.GuardedSqueeze.__init__(self, functions, constants, names, previous, length, active, failure, clear_error)
        self.cursor, self.stage_fault = cursor, stage_fault
        self.in_fill = False
        self.copies, self.failed_copy, self.unwind = 0, 0, None

    def load(self, ptr, width):
        if self.in_fill:
            return fill.FillModel.load(self, ptr, width)
        return guard.GuardedSqueeze.load(self, ptr, width)

    def store(self, ptr, width, value):
        if self.in_fill:
            return fill.FillModel.store(self, ptr, width, value)
        return guard.GuardedSqueeze.store(self, ptr, width, value)

    def run(self, name, args, depth=0):
        if name == self.names['fill']:
            require(not self.in_fill and self.in_squeeze and self.load(model.Pointer('reader', 8), 1) == 0
                    and len(args) == 2 and args[0] == model.Pointer('storage')
                    and type(args[1]) is int and 1 <= args[1] <= self.names['rate'],
                    'original bounded staging fill under armed squeeze guard')
            self.iteration += 1
            self.chunk = args[1]
            self.events.append(('fill', self.chunk))
            self.copies, self.failed_copy, self.unwind = 0, 0, None
            if self.stage_fault and self.stage_fault[0] == self.iteration:
                _, kind, ordinal = self.stage_fault
                if kind == 'reject':
                    self.failed_copy = ordinal
                else:
                    self.unwind = 'permute' if kind == 'permute' else ('copy', ordinal)
            start = len(self.events)
            self.in_fill = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.in_fill = False
                self.events[start:] = [('stage', *event) for event in self.events[start:]]
        if self.in_fill:
            return fill.FillModel.run(self, name, args, depth)
        return guard.GuardedSqueeze.run(self, name, args, depth)


def scenarios(rate, thorough):
    maximum = guard.squeeze.decode.limit.MAXIMUM
    lengths = (0, 1, rate, rate + 1, 2 * rate + 1) if thorough else (0, rate + 1)
    cursors = (0, rate - 1, rate, 255) if thorough else (rate, 255)
    for length in lengths:
        for cursor in cursors:
            for previous in (0, maximum - length, min(maximum, maximum - length + 1)) if thorough else (0, maximum):
                for active in (0, 1):
                    yield length, previous, active, None, None, cursor, None
    for length in (1, rate + 1):
        for active in (0, 1):
            for error in range(4) if thorough else (0, 3):
                yield length, 0, active, None, error, rate, None
    length = 2 * rate + 1 if thorough else rate + 1
    for cursor in (0, rate - 1, rate) if thorough else (rate - 1,):
        for iteration in range(1, (length + rate - 1) // rate + 1):
            for kind, ordinal in (('reject', 1), ('reject', 2), ('copy', 1), ('copy', 2), ('permute', 0)):
                yield length, 0, 1, None, None, cursor, (iteration, kind, ordinal)
            failures = [('write', iteration, error) for error in (range(4) if thorough else (0, 3))]
            failures += [('slice', iteration, None), ('copy', iteration, 'unwind')]
            for failure in failures:
                yield length, 0, 1, failure, None, cursor, None


def expected_inner(names, length, previous, cursor, failure, stage_fault):
    events, progress = [('counter-read',)], 0
    if previous + length > guard.squeeze.decode.limit.MAXIMUM:
        return events, progress, 2, cursor
    for iteration, offset in enumerate(range(0, length, names['rate']), 1):
        chunk = min(names['rate'], length - offset)
        events.append(('fill', chunk))
        failed, unwind = 0, None
        if stage_fault and stage_fault[0] == iteration:
            _, kind, ordinal = stage_fault
            if kind == 'reject':
                failed = ordinal
            else:
                unwind = 'permute' if kind == 'permute' else ('copy', ordinal)
        result, cursor, inner, unwound = fill.expected(names['rate'], chunk, cursor, names['success'] == 5, failed, unwind)
        events.extend(('stage', *event) for event in inner)
        if unwound or result != names['success']:
            return events, progress, 'unwind' if unwound else result, cursor
        if failure == ('slice', iteration, None):
            return events + [('slice-failure',)], progress, 3, cursor
        if failure and failure[:2] == ('write', iteration):
            return events + [('write-failure', failure[2]), ('wipe', 'storage', 584, 168)], progress, 4, cursor
        events.append(('copy', chunk))
        if failure == ('copy', iteration, 'unwind'):
            return events, progress, 'unwind', cursor
        progress += chunk
        events += [('progress', progress), ('wipe', 'storage', 584, 168)]
    if length:
        events.append(('counter-write',))
    return events, progress, None, cursor


def inspect(case, thorough=True):
    producer, names, merged = closure(case)
    functions, constants = guard.begin.functions_and_constants(case, merged)
    cleanup = [('wipe', 'storage', offset, width) for offset, width in guard.begin.guard.final.regions()]
    count, visited = 0, set()
    for length, previous, active, failure, clear_error, cursor, stage_fault in scenarios(names['rate'], thorough):
        machine = FilledSqueeze(functions, constants, names, previous, length, active, failure, clear_error, cursor, stage_fault)
        result = machine.allocate('result', 24)
        reader = machine.allocate('reader', 16)
        storage = machine.allocate('storage', 1040, payload=True)
        output = machine.allocate('output', length, payload=True)
        machine.fields(reader, [(0, 8, storage), (8, 1, active)])
        machine.events.clear()
        unwound = False
        try:
            require(machine.run(producer, [result, reader, output, length, 0, model.UNKNOWN]) is None, 'void composed byte producer')
        except model.Unwind as error:
            require(error.value == machine.exception, 'original primitive exception resumes through outer guard')
            unwound = True
        expected, progress, error, final_cursor = [('begin',)], 0, None, cursor
        output_clear = [('wipe', 'output', 0, length)] if length else []
        error_fields = lambda value: [('result', 8, 1, value), ('result', 0, 8, 2)]
        if clear_error is not None:
            expected += [('clear-error', clear_error), ('reader', 8, 1, 0)] + cleanup + error_fields(4)
        else:
            expected += output_clear
            if not active:
                expected += error_fields(0) + output_clear
            else:
                expected += [('reader', 8, 1, 0), ('operation',)]
                inner, progress, error, final_cursor = expected_inner(names, length, previous, cursor, failure, stage_fault)
                expected += inner
                if error == 'unwind':
                    expected += output_clear + cleanup
                elif error is not None:
                    expected += output_clear + error_fields(error) + cleanup
                else:
                    expected += [('finish',), ('reader', 8, 1, 1)]
                    expected += [('result', *field) for field in (
                        ((8, 8, output), (16, 8, length), (0, 8, 1)) if length else ((0, 8, 0),))]
        require(machine.events == expected and unwound == (error == 'unwind'),
                'exact fill/squeeze/guard event order and unwind: ' + repr((length, previous, active, failure, clear_error, cursor, stage_fault))
                + '; difference=' + repr(next(((i, a, b) for i, (a, b) in enumerate(zip(machine.events, expected)) if a != b),
                    ('lengths', len(machine.events), len(expected)))))
        success = active and clear_error is None and error is None
        committed = success and length > 0
        value = previous + length if committed else previous
        require(machine.cursor == final_cursor and machine.progress == progress
                and machine.load(reader, 8) == storage and machine.load(model.Pointer('reader', 8), 1) == int(success)
                and machine.counter_bytes == value.to_bytes(16, 'little')
                and machine.writes == (list(enumerate(value.to_bytes(16, 'little'))) if committed else [])
                and machine.reads == (list(range(16)) if active and clear_error is None else []),
                'exact algorithm cursor/progress/counter writes and success-only reader reuse')
        # Cursor/counter observations track algorithm writes before opaque wipe
        # requests, not a promise that these values survive actual clearing.
        visited.update(machine.visited)
        count += 1
    return count, merged, visited


def main(record, shard=None):
    before = comparison.capture.sources()
    cases = list(guard.begin.guard.final.cases(record))
    require(len(cases) == 16 and (shard is None or shard in range(4)), 'sixteen paths and valid shard')
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    counts = []
    for case in chosen:
        count, merged, _ = inspect(case)
        counts.append(count)
        print(f'Filled guarded byte squeeze: {count} cases; {len(merged)} functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print('Filled guarded cases: ' + str(sum(counts)))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Scalar/copy/volatile bodies opaque; no final-bit/whole-verifier/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
