#!/usr/bin/env python3
"""Compose retained portable debug byte squeezing with its actual owner guard."""
import argparse
import json
from pathlib import Path

import check_debug_squeeze_operation as squeeze

begin, model, require = squeeze.begin, squeeze.model, squeeze.require
comparison = squeeze.comparison
operation = squeeze.decode.limit.operation


class GuardedSqueeze(squeeze.SqueezeModel):
    def __init__(self, functions, constants, names, previous, length, active, failure, clear_error):
        super().__init__(functions, constants, names, previous, length, failure)
        self.active, self.clear_error = active, clear_error
        self.initializer = None
        self.in_squeeze = False
        self.progress = 0
        self.step_limit = 120000

    def store(self, ptr, width, value):
        super().store(ptr, width, value)
        if self.in_squeeze and ptr == model.Pointer(self.initializer.region, self.initializer.offset + 16):
            require(width == 8 and type(value) is int and 0 <= value <= self.length,
                    'bounded original initializer progress')
            self.progress = value
            self.events.append(('progress', value))

    def run(self, name, args, depth=0):
        if name == self.names['squeeze']:
            require(len(args) == 3 and args[0] == model.Pointer('storage') and args[2] == self.length
                    and self.length > 0 and self.load(model.Pointer('reader', 8), 1) == 0,
                    'actual nonempty byte squeeze under armed original guard')
            self.initializer = args[1]
            require(isinstance(self.initializer, model.Pointer), 'borrowed actual initializer')
            at = lambda offset: self.load(model.Pointer(self.initializer.region, self.initializer.offset + offset), 8)
            require((at(0), at(8), at(16)) == (model.Pointer('output'), self.length, 0),
                    'complete original zero-progress initializer reaches squeeze')
            self.in_squeeze = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.in_squeeze = False
        if name in (self.names['fill'], self.names['copy'], self.names['output_write']):
            require(self.in_squeeze and self.load(model.Pointer('reader', 8), 1) == 0,
                    'original guard stays armed throughout fill and output transfer')
        if name == self.names['output_write']:
            require(args == [self.initializer, model.Pointer('storage', 584), self.chunk],
                    'write uses original borrowed initializer and staging')
            if self.failure and self.failure[:2] == ('write', self.iteration):
                self.events.append(('write-failure', self.failure[2]))
                return self.failure[2]
            return model.Model.run(self, name, args, depth)
        if name == self.names['copy']:
            require(args == [model.Pointer('output', self.progress), model.Pointer('storage', 584), self.chunk],
                    'actual copy uses original destination prefix')
            self.address(args[0], args[2], access=False)
            self.address(args[1], args[2], access=False)
            self.events.append(('copy', self.chunk))
            if self.failure == ('copy', self.iteration, 'unwind'):
                raise model.Unwind(self.exception)
            return None
        if name == self.names['final_squeeze']:
            raise ValueError('final-bit body is outside this byte-only composition')
        return super().run(name, args, depth)


def scenarios(rate, thorough):
    maximum = squeeze.decode.limit.MAXIMUM
    for length in (0, 1, rate - 1, rate, rate + 1, 2 * rate + 1) if thorough else (0, rate + 1):
        for previous in (0, (1 << 64) - 1, maximum - length, min(maximum, maximum - length + 1)) if thorough else (0, maximum):
            for active in (0, 1):
                yield length, previous, active, None, None
                if length:
                    for error in range(4) if thorough else (0, 3):
                        yield length, previous, active, None, error
            if previous + length > maximum:
                continue
            for iteration in range(1, (length + rate - 1) // rate + 1) if thorough else ((2,) if length else ()):
                failures = [('fill', iteration, error) for error in (range(5) if thorough else (0, 4))]
                failures += [('write', iteration, error) for error in (range(4) if thorough else (0, 3))]
                failures += [('slice', iteration, None), ('fill', iteration, 'unwind'), ('copy', iteration, 'unwind')]
                for failure in failures:
                    yield length, previous, 1, failure, None


def expected_squeeze(length, previous, rate, failure):
    events, progress = [('counter-read',)], 0
    if previous + length > squeeze.decode.limit.MAXIMUM:
        return events, progress, 2
    for iteration, offset in enumerate(range(0, length, rate), 1):
        chunk = min(rate, length - offset)
        events.append(('fill', chunk))
        if failure and failure[:2] == ('fill', iteration):
            return events, progress, failure[2]
        if failure == ('slice', iteration, None):
            return events + [('slice-failure',)], progress, 3
        if failure and failure[:2] == ('write', iteration):
            return events + [('write-failure', failure[2]), ('wipe', 'storage', 584, 168)], progress, 4
        events.append(('copy', chunk))
        if failure == ('copy', iteration, 'unwind'):
            return events, progress, 'unwind'
        progress += chunk
        events += [('progress', progress), ('wipe', 'storage', 584, 168)]
    if length:
        events.append(('counter-write',))
    return events, progress, None


def inspect(case, thorough=True):
    producer, _, _, _ = operation.closure(case)
    names, selected, merged = squeeze.closure(case)
    functions, constants = begin.functions_and_constants(case, merged)
    cleanup = [('wipe', 'storage', offset, width) for offset, width in begin.guard.final.regions()]
    count, visited = 0, set()
    for length, previous, active, failure, clear_error in scenarios(names['rate'], thorough):
        machine = GuardedSqueeze(functions, constants, names, previous, length, active, failure, clear_error)
        result = machine.allocate('result', 24)
        reader = machine.allocate('reader', 16)
        storage = machine.allocate('storage', 1040, payload=True)
        destination = machine.allocate('output', length, payload=True)
        machine.fields(reader, [(0, 8, storage), (8, 1, active)])
        machine.events.clear()
        unwinds = failure is not None and failure[2] == 'unwind'
        try:
            require(machine.run(producer, [result, reader, destination, length, 0, model.UNKNOWN]) is None,
                    'void actual guarded producer')
        except model.Unwind as error:
            require(unwinds and error.value == machine.exception, 'original squeeze exception resumes through guard')
        else:
            require(not unwinds, 'guard does not swallow squeeze unwind')
        expected, progress, error = [('begin',)], 0, None
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
                inner, progress, error = expected_squeeze(length, previous, names['rate'], failure)
                expected += inner
                if error == 'unwind':
                    expected += output_clear + cleanup
                elif error is not None:
                    expected += output_clear + error_fields(error) + cleanup
                else:
                    expected += [('finish',), ('reader', 8, 1, 1)]
                    fields = ((8, 8, destination), (16, 8, length), (0, 8, 1)) if length else ((0, 8, 0),)
                    expected += [('result', *field) for field in fields]
        require(machine.events == expected, 'composed exact squeeze/progress/completion and output/owner cleanup ordering')
        success = active and clear_error is None and error is None
        require(machine.load(reader, 8) == storage and machine.load(model.Pointer('reader', 8), 1) == int(success),
                'original owner and success-only reusable reader')
        require(machine.progress == progress, 'actual initialized prefix before transfer or destruction')
        committed = success and length > 0
        value = previous + length if committed else previous
        # Wipe primitives are explicit boundaries: counter_bytes records observed
        # algorithm writes, not the contents after the outer volatile wipe request.
        require(machine.counter_bytes == value.to_bytes(16, 'little')
                and machine.writes == (list(enumerate(value.to_bytes(16, 'little'))) if committed else [])
                and machine.reads == (list(range(16)) if active and clear_error is None else []),
                'exact algorithm counter reads and success-only commit before cleanup boundaries')
        visited.update(machine.visited)
        count += 1
    return count, selected, merged, visited


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in begin.guard.final.cases(record)]
    require(len(results) == 16 and before == comparison.capture.sources(), 'complete unchanged composed byte-squeeze matrix')
    print('Debug guarded byte squeeze: ' + repr([(count, len(merged)) for count, _, merged, _ in results]) + ' PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Fill/copy/volatile bodies remain boundaries; no final-bit, arbitrary-unwind, register/spill or native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
