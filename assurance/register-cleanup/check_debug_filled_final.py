#!/usr/bin/env python3
"""Compose retained staging fill with final-bit squeezing and its owner guard."""
import argparse
import json
from pathlib import Path

import check_debug_filled_squeeze as byte
import check_debug_final_guard as final

fill, model, require, comparison = byte.fill, byte.model, byte.require, byte.comparison


def closure(case):
    producer, names, merged = byte.closure(case)
    outer_names, _, outer = final.final.closure(case)
    for key, value in outer_names.items():
        require(key not in names or key == 'panics' or names[key] == value, 'same final/fill helper identities')
    panics = names['panics'] | outer_names['panics']
    names.update(outer_names)
    names['panics'] = panics
    for name, body in outer.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical shared final/fill helper')
        merged[name] = body
    return producer, names, merged


class FilledFinal(fill.FillModel, final.GuardedFinal):
    def __init__(self, functions, constants, names, previous, length, valid, active, failure, clear_error, cursor, stage_fault):
        # Keep the actual final producer/initializer state; do not invoke the
        # standalone staging constructor, which would reset the outer guard.
        final.GuardedFinal.__init__(self, functions, constants, names, previous, length, valid, active, failure, clear_error)
        self.cursor, self.stage_fault = cursor, stage_fault
        self.in_fill = False
        self.copies, self.failed_copy, self.unwind = 0, 0, None

    def load(self, ptr, width):
        if self.in_fill:
            return fill.FillModel.load(self, ptr, width)
        return final.GuardedFinal.load(self, ptr, width)

    def store(self, ptr, width, value):
        if self.in_fill:
            return fill.FillModel.store(self, ptr, width, value)
        return final.GuardedFinal.store(self, ptr, width, value)

    def run(self, name, args, depth=0):
        if name == self.names['fill']:
            # The byte composition's entry interprets the actual fill body,
            # while this class retains final-tail dispatch outside that body.
            return byte.FilledSqueeze.run(self, name, args, depth)
        if self.in_fill:
            return fill.FillModel.run(self, name, args, depth)
        return final.GuardedFinal.run(self, name, args, depth)


def scenarios(rate, thorough):
    maximum = final.final.squeeze.decode.limit.MAXIMUM
    lengths = (1, rate, rate + 1, 2 * rate + 1) if thorough else (1, rate + 1)
    shapes = [(0, 0)] + [(length, valid) for length in lengths for valid in (range(1, 9) if thorough else (1, 7, 8))]
    for length, valid in shapes:
        prefix = length if valid in (0, 8) else length - 1
        for cursor in (0, rate - 1, rate, 255) if thorough else (rate, 255):
            for previous in (0, maximum - prefix, min(maximum, maximum - prefix + 1)) if thorough else (0, maximum):
                for active in (0, 1):
                    yield length, valid, previous, active, None, None, cursor, None
    for length, valid in ((1, 1), (rate + 1, 7)):
        for active in (0, 1):
            for error in range(4) if thorough else (0, 3):
                yield length, valid, 0, active, None, error, rate, None
    for valid in (1, 7, 8):
        length = 2 * rate + 1 if thorough else rate + 1
        prefix = length if valid == 8 else length - 1
        iterations = (prefix + rate - 1) // rate + int(prefix != length)
        for cursor in (0, rate - 1, rate) if thorough else (rate - 1,):
            for iteration in range(1, iterations + 1):
                for kind, ordinal in (('reject', 1), ('reject', 2), ('copy', 1), ('copy', 2), ('permute', 0)):
                    yield length, valid, 0, 1, None, None, cursor, (iteration, kind, ordinal)
                failures = [('write', iteration, error) for error in (range(4) if thorough else (0, 3))]
                failures += [('first' if valid != 8 and iteration == iterations else 'slice', iteration, None),
                             ('copy', iteration, 'unwind')]
                for failure in failures:
                    yield length, valid, 0, 1, failure, None, cursor, None


def expected_inner(names, previous, length, valid, cursor, failure, stage_fault):
    # Expand the independent final-shape oracle using the independent staging
    # geometry oracle. A real staging rejection replaces the opaque fill result
    # at that iteration; no model events are used to build the expectation.
    events, _, _, _ = final.final.expected(names, previous, length, valid, failure)
    expanded, iteration, fault = [], 0, None
    for event in events:
        expanded.append(event)
        if event[0] != 'fill':
            continue
        iteration += 1
        failed, unwind = 0, None
        if stage_fault and stage_fault[0] == iteration:
            _, kind, ordinal = stage_fault
            if kind == 'reject':
                failed = ordinal
            else:
                unwind = 'permute' if kind == 'permute' else ('copy', ordinal)
        result, cursor, inner, unwound = fill.expected(names['rate'], event[1], cursor, names['success'] == 5, failed, unwind)
        expanded.extend(('stage', *part) for part in inner)
        if unwound or result != names['success']:
            fault = ('fill', iteration, 'unwind' if unwound else result)
            break
    original, progress, committed, error = final.final.expected(names, previous, length, valid, fault or failure)
    if fault:
        require(sum(event[0] == 'fill' for event in original) == iteration, 'oracle stops at rejected staging iteration')
    return [('progress', event[3]) if event[0] == 'store' else event for event in expanded], progress, committed, error, cursor


def inspect(case, thorough=True):
    producer, names, merged = closure(case)
    functions, constants = final.begin.functions_and_constants(case, merged)
    cleanup = [('wipe', 'storage', offset, width) for offset, width in final.begin.guard.final.regions()]
    count, visited = 0, set()
    for length, valid, previous, active, failure, clear_error, cursor, stage_fault in scenarios(names['rate'], thorough):
        machine = FilledFinal(functions, constants, names, previous, length, valid, active, failure, clear_error, cursor, stage_fault)
        result = machine.allocate('result', 24)
        reader = machine.allocate('reader', 16)
        storage = machine.allocate('storage', 1040, payload=True)
        output = machine.allocate('output', length, payload=True)
        machine.fields(reader, [(0, 8, storage), (8, 1, active)])
        machine.events.clear()
        unwound = False
        try:
            require(machine.run(producer, [result, reader, output, length, 1, valid]) is None, 'void filled final producer')
        except model.Unwind as error:
            require(error.value == machine.exception, 'original staging/final exception resumes through guard')
            unwound = True
        expected, progress, committed, error, reads, final_cursor = [('begin',)], 0, False, None, 0, cursor
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
                if length:
                    inner, progress, committed, error, final_cursor = expected_inner(names, previous, length, valid, cursor, failure, stage_fault)
                    error = None if error == names['success'] else error
                else:
                    inner = [('counter-read',)]
                reads = sum(event == ('counter-read',) for event in inner)
                expected += inner
                if error == 'unwind':
                    expected += output_clear + cleanup
                elif error is not None:
                    expected += output_clear + error_fields(error) + cleanup
                else:
                    expected += [('finish',), ('reader', 8, 1, 1)]
                    fields = ((8, 8, output), (16, 8, length), (0, 8, 1)) if length else ((0, 8, 0),)
                    expected += [('result', *field) for field in fields]
        require(machine.events == expected and unwound == (error == 'unwind'),
                'exact staging/final/guard trace: ' + repr((length, valid, previous, active, failure, clear_error, cursor, stage_fault))
                + '; difference=' + repr(next(((i, a, b) for i, (a, b) in enumerate(zip(machine.events, expected)) if a != b),
                    ('lengths', len(machine.events), len(expected)))))
        success = active and clear_error is None and error is None
        value = previous + machine.prefix if committed else previous
        require(machine.cursor == final_cursor and machine.progress == progress
                and machine.load(reader, 8) == storage and machine.load(model.Pointer('reader', 8), 1) == int(success)
                and machine.counter_bytes == value.to_bytes(16, 'little')
                and machine.writes == (list(enumerate(value.to_bytes(16, 'little'))) if committed else [])
                and machine.reads == list(range(16)) * reads,
                'exact cursor/progress and prefix commit, including tail failure before opaque cleanup')
        visited.update(machine.visited)
        count += 1
    return count, merged, visited


def main(record, shard=None):
    before = comparison.capture.sources()
    cases = list(final.begin.guard.final.cases(record))
    require(len(cases) == 16 and (shard is None or shard in range(4)), 'sixteen paths and valid shard')
    counts = []
    for case in cases if shard is None else cases[4 * shard:4 * shard + 4]:
        count, merged, _ = inspect(case)
        counts.append(count)
        print(f'Filled guarded final squeeze: {count} cases; {len(merged)} functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print('Filled final cases: ' + str(sum(counts)))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Primitive bodies opaque; no consuming/whole-verifier/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
