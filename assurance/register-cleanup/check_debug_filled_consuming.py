#!/usr/bin/env python3
"""Compose retained consuming readers with staging-filled final-bit producers."""
import argparse
import json
from pathlib import Path

import check_debug_consuming_final as consuming
import check_debug_filled_final as filled

model, require, comparison = filled.model, filled.require, filled.comparison
fill = filled.fill


def closure(case):
    producer, names, merged = filled.closure(case)
    outer_producer, wipe, constructor, outer = consuming.bridge.closure(case)
    require(producer == outer_producer and wipe == names['wipe'], 'same consuming producer and clearing boundary')
    for name, body in outer.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical shared filled/consuming helper')
        merged[name] = body
    return producer, constructor, names, merged


class FilledConsuming(fill.FillModel, consuming.ConsumingFinal):
    def __init__(self, functions, constants, names, previous, length, valid, active,
                 producer, constructor, failure, clear_error, cursor, stage_fault, constructor_fault=False):
        # Preserve the original consuming model's compiler-local reader binding.
        # The standalone fill constructor would reset that surrounding state.
        consuming.ConsumingFinal.__init__(self, functions, constants, names, previous, length, valid, active,
                                         producer, constructor, failure, clear_error, constructor_fault)
        self.cursor, self.stage_fault = cursor, stage_fault
        self.in_fill = False
        self.copies, self.failed_copy, self.unwind = 0, 0, None

    def load(self, ptr, width):
        if self.in_fill:
            return fill.FillModel.load(self, ptr, width)
        return consuming.ConsumingFinal.load(self, ptr, width)

    def store(self, ptr, width, value):
        if self.in_fill:
            return fill.FillModel.store(self, ptr, width, value)
        return consuming.ConsumingFinal.store(self, ptr, width, value)

    def run(self, name, args, depth=0):
        if name == self.names['fill']:
            require(self.in_producer, 'staging fill remains inside the actual consuming producer')
            return filled.byte.FilledSqueeze.run(self, name, args, depth)
        if self.in_fill:
            return fill.FillModel.run(self, name, args, depth)
        return consuming.ConsumingFinal.run(self, name, args, depth)


def scenarios(rate, thorough):
    for values in filled.scenarios(rate, thorough):
        yield (*values, False)
    for length, valid in ((0, 1), (1, 0), (1, 9), ((1 << 61) + 1, 8), (1, 7)):
        for active in (0, 1):
            for fault in (False, True):
                if fault or (length, valid) != (1, 7):
                    yield length, valid, 0, active, None, None, rate, None, fault


def producer_trace(names, length, valid, previous, active, failure, clear_error, cursor, stage_fault, cleanup):
    # Independent lifecycle envelope around the existing final-shape/staging
    # oracles. Never execute a second copy of the producer as its own oracle.
    events, progress, committed, error, reads = [('begin',)], 0, False, None, 0
    output_clear = [('wipe', 'output', 0, length)] if length else []
    errors = lambda value: [('result', 8, 1, value), ('result', 0, 8, 2)]
    if clear_error is not None:
        error = 4
        events += [('clear-error', clear_error), ('reader', 8, 1, 0)] + cleanup + errors(error)
    else:
        events += output_clear
        if not active:
            error = 0
            events += errors(error) + output_clear
        else:
            events += [('reader', 8, 1, 0), ('operation',)]
            if length:
                inner, progress, committed, error, cursor = filled.expected_inner(
                    names, previous, length, valid, cursor, failure, stage_fault)
                error = None if error == names['success'] else error
            else:
                inner = [('counter-read',)]
            reads = sum(event == ('counter-read',) for event in inner)
            events += inner
            if error == 'unwind':
                events += output_clear + cleanup
            elif error is not None:
                events += output_clear + errors(error) + cleanup
            else:
                events += [('finish',), ('reader', 8, 1, 1)]
                fields = ((8, 8, model.Pointer('output')), (16, 8, length), (0, 8, 1)) if length else ((0, 8, 0),)
                events += [('result', *field) for field in fields]
    return events, progress, committed, error, reads, cursor


def inspect(case, thorough=True):
    producer, constructor, names, merged = closure(case)
    functions, constants = consuming.begin.functions_and_constants(case, merged)
    cleanup = [('wipe', 'storage', offset, width) for offset, width in consuming.bridge.regions()]
    count, visited = 0, set()
    for length, valid, previous, active, failure, clear_error, cursor, stage_fault, fault in scenarios(names['rate'], thorough):
        machine = FilledConsuming(functions, constants, names, previous, length, valid, active,
                                  producer, constructor, failure, clear_error, cursor, stage_fault, fault)
        unwound = consuming.run(machine, case.root, length, valid, active, True)
        shape = valid == 0 if length == 0 else 1 <= valid <= 8
        admitted = shape and (length == 0 or (length - 1) * 8 + valid <= model.MASK)
        progress, committed, reads, final_cursor = 0, False, 0, cursor
        if fault:
            expected = [('constructor-unwind',)] + cleanup
            require(unwound and machine.producer_calls == 0, 'constructor unwind clears owner without entering producer')
        elif not admitted:
            expected = [('result', 8, 1, 18 if case.enabled else 6), ('result', 0, 8, 2)] + cleanup
            require(not unwound and machine.producer_calls == 0, 'invalid shape rejected before initialization/producer')
        else:
            trace, progress, committed, error, reads, final_cursor = producer_trace(
                names, length, valid, previous, active, failure, clear_error, cursor, stage_fault, cleanup)
            require(unwound == (error == 'unwind') and machine.producer_calls == 1,
                    'one consuming producer with original unwind outcome')
            expected = [('producer-enter',)] + trace + [('producer-exit',)] + cleanup
            if not unwound:
                if error is not None:
                    mapped = (0, 3, 4, 4, 5)[error] + (12 if case.enabled else 0)
                    expected += [('result', 8, 1, mapped), ('result', 0, 8, 2)]
                else:
                    if length:
                        expected += [('result', 8, 8, model.Pointer('output')), ('result', 16, 8, length)]
                    expected += [('result', 0, 8, int(length != 0))]
            require(machine.load(machine.reader_address, 8) == model.Pointer('storage'), 'original consumed owner binding')
        require(machine.events == expected, 'exact filled consuming trace: '
                + repr((length, valid, previous, active, failure, clear_error, cursor, stage_fault, fault))
                + '; difference=' + repr(next(((i, a, b) for i, (a, b) in enumerate(zip(machine.events, expected)) if a != b),
                    ('lengths', len(machine.events), len(expected)))))
        value = previous + machine.prefix if committed else previous
        require(machine.cursor == final_cursor and machine.progress == progress
                and machine.counter_bytes == value.to_bytes(16, 'little')
                and machine.writes == (list(enumerate(value.to_bytes(16, 'little'))) if committed else [])
                and machine.reads == list(range(16)) * reads and 'reader' not in machine.sizes
                and not machine.in_producer and not machine.in_fill and not machine.in_squeeze,
                'exact pre-clear cursor/counter/progress and exited original compiler-local reader binding')
        visited.update(machine.visited)
        count += 1
    return count, merged, visited


def main(record, shard=None):
    before = comparison.capture.sources()
    cases = list(consuming.bridge.cases(record))
    require(len(cases) == 16 and (shard is None or shard in range(4)), 'sixteen paths and valid shard')
    counts = []
    for case in cases if shard is None else cases[4 * shard:4 * shard + 4]:
        count, merged, _ = inspect(case)
        counts.append(count)
        print(f'Filled consuming final: {count} cases; {len(merged)} functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print('Filled consuming cases: ' + str(sum(counts)))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Primitive bodies opaque; no whole-verifier/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
