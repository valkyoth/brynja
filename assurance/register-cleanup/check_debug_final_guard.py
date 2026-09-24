#!/usr/bin/env python3
"""Compose retained final-bit squeezing with the actual portable producer guard."""
import argparse
import json
from pathlib import Path

import check_debug_final_squeeze as final
import check_debug_squeeze_guard as guarded

model, require, comparison = final.model, final.require, final.comparison
begin = final.squeeze.begin


class GuardedFinal(final.FinalModel):
    def __init__(self, functions, constants, names, previous, length, valid, active, failure=None, clear_error=None):
        super().__init__(functions, constants, names, previous, length, valid, failure)
        self.mode, self.active, self.clear_error = 1, active, clear_error
        self.initializer, self.in_squeeze, self.progress = None, False, 0

    def store(self, ptr, width, value):
        super().store(ptr, width, value)
        if self.in_squeeze and ptr == model.Pointer(self.initializer.region, self.initializer.offset + 16):
            require(width == 8 and type(value) is int and 0 <= value <= self.total,
                    'bounded original final initializer progress')
            self.progress = value
            self.events.append(('progress', value))

    def armed(self):
        require(self.in_squeeze and self.load(model.Pointer('reader', 8), 1) == 0,
                'original guard remains armed throughout final-bit processing')

    def run(self, name, args, depth=0):
        if name == self.names['final_squeeze']:
            require(len(args) == 4 and args[:3] == [model.Pointer('storage'), self.total, self.valid]
                    and self.total > 0 and self.mode == 1 and not self.in_squeeze
                    and self.load(model.Pointer('reader', 8), 1) == 0,
                    'actual nonempty final-bit squeeze under original armed guard')
            self.initializer = args[3]
            require(isinstance(self.initializer, model.Pointer), 'borrowed actual final initializer')
            at = lambda offset: self.load(model.Pointer(self.initializer.region, self.initializer.offset + offset), 8)
            require((at(0), at(8), at(16)) == (model.Pointer('output'), self.total, 0),
                    'complete original zero-progress final initializer')
            self.in_squeeze = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.in_squeeze = False
        if name == self.names['squeeze']:
            self.armed()
            require(args == [model.Pointer('storage'), self.initializer, self.prefix] and not self.prefix_done,
                    'original final initializer and exact complete-byte prefix')
            result = model.Model.run(self, name, args, depth)
            self.prefix_done = result == self.names['success']
            return result
        if name in (self.names[key] for key in ('fill', 'copy', 'output_write', 'apply_mask')):
            self.armed()
        if name == self.names['output_write']:
            require(args == [self.initializer, model.Pointer('storage', 584), self.chunk],
                    'final write uses original initializer and staging')
            if self.failure and self.failure[:2] == ('write', self.iteration):
                self.events.append(('write-failure', self.failure[2]))
                return self.failure[2]
            return model.Model.run(self, name, args, depth)
        if name == self.names['copy']:
            require(args == [model.Pointer('output', self.progress), model.Pointer('storage', 584), self.chunk],
                    'final copy uses original initialized output prefix')
            self.address(args[0], args[2], access=False)
            self.address(args[1], args[2], access=False)
            self.events.append(('copy', self.chunk))
            if self.failure == ('copy', self.iteration, 'unwind'):
                raise model.Unwind(self.exception)
            return None
        return super().run(name, args, depth)


def scenarios(rate, thorough):
    maximum = final.squeeze.decode.limit.MAXIMUM
    lengths = (1, rate, rate + 1, 2 * rate + 1) if thorough else (1, rate + 1)
    shapes = [(0, 0)] + [(length, valid) for length in lengths for valid in (range(1, 9) if thorough else (1, 7, 8))]
    for length, valid in shapes:
        prefix = length if valid in (0, 8) else length - 1
        counters = (0, maximum - prefix, min(maximum, maximum - prefix + 1)) if thorough else (0, maximum)
        for previous in counters:
            for active in (0, 1):
                yield length, valid, previous, active, None, None
            if previous == 0 and length in (1, rate + 1) and valid in (1, 8):
                for active in (0, 1):
                    for error in range(4) if thorough else (0, 3):
                        yield length, valid, previous, active, None, error
            if previous or length not in (1, 2 * rate + 1 if thorough else rate + 1) or valid not in (1, 7, 8):
                continue
            iterations = (prefix + rate - 1) // rate + int(prefix != length)
            for iteration in range(1, iterations + 1):
                tail = prefix != length and iteration == iterations
                failures = [('fill', iteration, error) for error in (range(5) if thorough else (0, 4))]
                failures += [('write', iteration, error) for error in (range(4) if thorough else (0, 3))]
                failures += [('first' if tail else 'slice', iteration, None),
                             ('fill', iteration, 'unwind'), ('copy', iteration, 'unwind')]
                for failure in failures:
                    yield length, valid, previous, 1, failure, None


def inspect(case, thorough=True):
    producer, _, _, _ = guarded.operation.closure(case)
    names, selected, merged = final.closure(case)
    functions, constants = begin.functions_and_constants(case, merged)
    cleanup = [('wipe', 'storage', offset, width) for offset, width in begin.guard.final.regions()]
    count, visited = 0, set()
    for length, valid, previous, active, failure, clear_error in scenarios(names['rate'], thorough):
        machine = GuardedFinal(functions, constants, names, previous, length, valid, active, failure, clear_error)
        result = machine.allocate('result', 24)
        reader = machine.allocate('reader', 16)
        storage = machine.allocate('storage', 1040, payload=True)
        destination = machine.allocate('output', length, payload=True)
        machine.fields(reader, [(0, 8, storage), (8, 1, active)])
        machine.events.clear()
        unwinds = failure is not None and failure[2] == 'unwind'
        try:
            require(machine.run(producer, [result, reader, destination, length, 1, valid]) is None,
                    'void actual guarded final producer')
        except model.Unwind as error:
            require(unwinds and error.value == machine.exception, 'original final exception resumes through guard')
        else:
            require(not unwinds, 'final guard does not swallow boundary unwind')
        expected, progress, committed, error, reads = [('begin',)], 0, False, None, 0
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
                    inner, progress, committed, error = final.expected(names, previous, length, valid, failure)
                    reads = sum(event == ('counter-read',) for event in inner)
                    inner = [('progress', event[3]) if event[0] == 'store' else event for event in inner]
                    error = None if error == names['success'] else error
                else:
                    inner, reads = [('counter-read',)], 1
                expected += inner
                if error == 'unwind':
                    expected += output_clear + cleanup
                elif error is not None:
                    expected += output_clear + error_fields(error) + cleanup
                else:
                    expected += [('finish',), ('reader', 8, 1, 1)]
                    fields = ((8, 8, destination), (16, 8, length), (0, 8, 1)) if length else ((0, 8, 0),)
                    expected += [('result', *field) for field in fields]
        require(machine.events == expected, 'exact final-bit/guard/output/owner cleanup ordering')
        success = active and clear_error is None and error is None
        require(machine.load(reader, 8) == storage and machine.load(model.Pointer('reader', 8), 1) == int(success),
                'original owner and success-only producer reactivation')
        require(machine.progress == progress, 'exact initialized prefix before transfer or destruction')
        value = previous + machine.prefix if committed else previous
        require(machine.counter_bytes == value.to_bytes(16, 'little')
                and machine.writes == (list(enumerate(value.to_bytes(16, 'little'))) if committed else [])
                and machine.reads == list(range(16)) * reads,
                'exact counter reads and prefix commit before opaque outer clearing')
        visited.update(machine.visited)
        count += 1
    return count, selected, merged, visited


def main(record, shard=None):
    before = comparison.capture.sources()
    cases = list(begin.guard.final.cases(record))
    require(len(cases) == 16 and (shard is None or shard in range(4)), 'sixteen paths and valid optional shard')
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    results = []
    for case in chosen:
        result = inspect(case)
        results.append(result)
        print('Guarded final-bit path: ' + repr((result[0], len(result[2]))) + ' PASS', flush=True)
    require(len(results) == len(chosen) and before == comparison.capture.sources(), 'unchanged complete selected guarded matrix')
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; paths {4 * shard}..{4 * shard + 3}'))
    print('Guarded final-bit cases: ' + str(sum(result[0] for result in results)))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Secret primitives remain opaque; consuming-reader wrapper not composed; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4), help='only this quarter; all four required')
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
