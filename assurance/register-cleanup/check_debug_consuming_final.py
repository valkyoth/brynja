#!/usr/bin/env python3
"""Compose retained consuming readers with their actual guarded final producer."""
import argparse
import json
from pathlib import Path

import check_debug_final_guard as guard

begin, model, require, comparison = guard.begin, guard.model, guard.require, guard.comparison
bridge = begin.guard.final


def closure(case):
    producer, wipe, constructor, outer = bridge.closure(case)
    guarded_producer, _, _, _ = guard.guarded.operation.closure(case)
    names, _, inner = guard.final.closure(case)
    require(producer == guarded_producer and wipe == names['wipe'], 'same actual producer and clearing primitive')
    merged = dict(inner)
    for name, body in outer.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical shared consuming/producer helper')
        merged[name] = body
    return producer, constructor, names, merged


class ConsumingFinal(guard.GuardedFinal):
    def __init__(self, functions, constants, names, previous, length, valid, active,
                 producer, constructor, failure=None, clear_error=None, constructor_fault=False):
        super().__init__(functions, constants, names, previous, length, valid, active, failure, clear_error)
        constructor_model = bridge.constructor.ConstructorModel(functions, constants)
        for key, size in constructor_model.sizes.items():
            require(key not in self.sizes or self.sizes[key] == size, 'same immutable constructor constant size')
            self.sizes[key] = size
        for key, value in constructor_model.memory.items():
            require(key not in self.memory or self.memory[key] == value, 'same immutable constructor constant value')
            self.memory[key] = value
        self.producer, self.constructor = producer, constructor
        self.constructor_fault = constructor_fault
        self.reader_address = self.producer_result = None
        self.in_producer, self.producer_calls = False, 0

    def load(self, ptr, width):
        # Only the diagnostic guard hooks use this symbolic address. LLVM still
        # reads/writes its original compiler-local descriptor, without copying
        # or manufacturing its fields. No 'reader' allocation exists here.
        if isinstance(ptr, model.Pointer) and ptr.region == 'reader':
            require(self.in_producer and self.reader_address is not None and ptr.offset in (0, 8),
                    'symbolic guard observation bound to active actual reader')
            ptr = model.Pointer(self.reader_address.region, self.reader_address.offset + ptr.offset)
        return super().load(ptr, width)

    def store(self, ptr, width, value):
        super().store(ptr, width, value)
        if self.in_producer:
            for role, base, size in (('reader', self.reader_address, 16), ('result', self.producer_result, 24)):
                if ptr.region == base.region and base.offset <= ptr.offset < base.offset + size:
                    require(ptr.offset + width <= base.offset + size, 'bounded actual producer descriptor write')
                    self.events.append((role, ptr.offset - base.offset, width, value))

    def run(self, name, args, depth=0):
        if name == 'llvm.umul.with.overflow.i64':
            return bridge.constructor.ConstructorModel.run(self, name, args, depth)
        if name == self.constructor and self.constructor_fault:
            self.events.append(('constructor-unwind',))
            raise model.Unwind(self.exception)
        if name == self.producer:
            require(not self.in_producer and self.producer_calls == 0 and len(args) == 6,
                    'one actual consuming producer handoff')
            result, reader = args[:2]
            require(isinstance(result, model.Pointer) and isinstance(reader, model.Pointer)
                    and result.region not in ('result', 'storage', 'output', 'reader')
                    and reader.region not in ('result', 'storage', 'output', 'reader')
                    and self.load(reader, 8) == model.Pointer('storage')
                    and self.load(model.Pointer(reader.region, reader.offset + 8), 1) == self.active
                    and args[2:] == [model.Pointer('output'), self.total, 1, self.valid],
                    'original compiler-local reader/result and exact destination/bit shape')
            self.address(result, 24, access=False)
            self.address(reader, 16, access=False)
            self.reader_address, self.producer_result = reader, result
            self.producer_calls += 1
            self.events.append(('producer-enter',))
            self.in_producer = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.in_producer = False
                self.events.append(('producer-exit',))
        return super().run(name, args, depth)


def run(machine, root, length, valid, active, consuming):
    result = machine.allocate('result', 24)
    storage = machine.allocate('storage', 1040, payload=True)
    output = machine.allocate('output', length, payload=True)
    if consuming:
        args = [result, storage, active, output, length, valid]
    else:
        reader = machine.allocate('reader', 16)
        machine.fields(reader, [(0, 8, storage), (8, 1, active)])
        args = [result, reader, output, length, 1, valid]
    machine.events.clear()
    try:
        require(machine.run(root, args) is None, 'void final result ABI')
    except model.Unwind as error:
        require(error.value == machine.exception, 'original final exception preserved')
        return True
    return False


def inspect(case, thorough=True):
    # First check the producer independently against its arithmetic, lifecycle
    # and event-order oracle. The composition below must preserve that trace,
    # not merely agree with another unchecked execution of the same code.
    guard.inspect(case, thorough)
    producer, constructor, names, merged = closure(case)
    functions, constants = begin.functions_and_constants(case, merged)
    cleanup = [('wipe', 'storage', offset, width) for offset, width in bridge.regions()]
    visited, count = set(), 0
    scenarios = [(length, valid, previous, active, failure, clear_error, False)
                 for length, valid, previous, active, failure, clear_error in guard.scenarios(names['rate'], thorough)]
    # Constructor rejection precedes initialization; it consumes the reader but
    # does not promise to clear a destination whose shape was never admitted.
    scenarios += [(length, valid, 0, active, None, None, fault)
                  for length, valid in ((0, 1), (1, 0), (1, 9), ((1 << 61) + 1, 8), (1, 7))
                  for active in (0, 1) for fault in (False, True)
                  if fault or (length, valid) != (1, 7)]
    for length, valid, previous, active, failure, clear_error, fault in scenarios:
        machine = ConsumingFinal(functions, constants, names, previous, length, valid, active,
                                 producer, constructor, failure, clear_error, fault)
        unwound = run(machine, case.root, length, valid, active, True)
        shape = (valid == 0 if length == 0 else 1 <= valid <= 8)
        admitted = shape and (length == 0 or (length - 1) * 8 + valid <= model.MASK)
        if fault:
            expected = [('constructor-unwind',)] + cleanup
            require(unwound and machine.producer_calls == 0, 'constructor unwind consumes original owner before producer')
        elif not admitted:
            expected = [('result', 8, 1, 18 if case.enabled else 6), ('result', 0, 8, 2)] + cleanup
            require(not unwound and machine.producer_calls == 0, 'invalid shape rejected before producer')
        else:
            reference = guard.GuardedFinal(functions, constants, names, previous, length, valid, active, failure, clear_error)
            reference_unwind = run(reference, producer, length, valid, active, False)
            require(unwound == reference_unwind and machine.producer_calls == 1,
                    'exactly one producer, same unwind outcome')
            expected = [('producer-enter',)] + reference.events + [('producer-exit',)] + cleanup
            if not unwound:
                tag = reference.load(model.Pointer('result'), 8)
                if tag == 2:
                    error = reference.load(model.Pointer('result', 8), 1)
                    mapped = (0, 3, 4, 4, 5)[error] + (12 if case.enabled else 0)
                    expected += [('result', 8, 1, mapped), ('result', 0, 8, 2)]
                else:
                    require(tag == int(length != 0), 'exact empty/nonempty successful result')
                    if length:
                        expected += [('result', 8, 8, model.Pointer('output')), ('result', 16, 8, length)]
                    expected += [('result', 0, 8, tag)]
            require(machine.counter_bytes == reference.counter_bytes and machine.reads == reference.reads
                    and machine.writes == reference.writes and machine.progress == reference.progress,
                    'same exact counter/progress effects through consuming wrapper')
        require(machine.events == expected, 'exact composed producer, consuming cleanup and public result ordering: '
                + repr((length, valid, previous, active, failure, clear_error, fault))
                + '; difference=' + repr(next(((index, left, right) for index, (left, right) in
                    enumerate(zip(machine.events, expected)) if left != right),
                    ('lengths', len(machine.events), len(expected)))))
        visited.update(machine.visited)
        count += 1
    return count, merged, visited


def main(record, shard=None):
    before = comparison.capture.sources()
    cases = list(bridge.cases(record))
    require(len(cases) == 16 and (shard is None or shard in range(4)), 'sixteen paths and valid shard')
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    counts = []
    for case in chosen:
        count, merged, _ = inspect(case)
        counts.append(count)
        print(f'Consuming final path: {count} cases; {len(merged)} functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print('Composed consuming cases: ' + str(sum(counts)))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Secret primitive bodies opaque; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
