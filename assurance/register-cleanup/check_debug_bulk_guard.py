#!/usr/bin/env python3
"""Compose retained portable bulk readers with the actual guarded byte producer."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path

import check_debug_kmac_bulk_bridge as bridge
import check_debug_squeeze_guard as guard

model, require, comparison = guard.model, guard.require, guard.comparison


@dataclass(frozen=True)
class Case:
    outer: bridge.Case
    inner: guard.begin.guard.final.Case


def cases(record):
    inner = list(guard.begin.guard.final.cases(record))
    for outer in bridge.cases(record):
        if outer.accelerated:
            continue
        matches = [item for item in inner if item.kmac == outer.kmac and item.sha3 == outer.sha3
                   and item.enabled == outer.enabled
                   and ('Cshake128Reader' in item.root) == ('Cshake128Reader' in outer.root)]
        require(len(matches) == 1, 'same configuration and strength for bulk/producer composition')
        yield Case(outer, matches[0])


def closure(case):
    require(case.outer.kmac == case.inner.kmac and case.outer.sha3 == case.inner.sha3
            and case.outer.enabled == case.inner.enabled and not case.outer.accelerated,
            'identical portable caller/producer artifacts')
    producer, outer = bridge.closure(case.outer)
    guarded, _, _, _ = guard.operation.closure(case.inner)
    names, _, merged = guard.squeeze.closure(case.inner)
    require(producer == guarded, 'actual bulk caller uses the checked producer')
    for name, body in outer.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical shared bulk/producer helper')
        merged[name] = body
    return producer, names, merged


class BulkGuard(guard.GuardedSqueeze):
    def __init__(self, functions, constants, names, previous, length, active, failure, clear_error, producer):
        super().__init__(functions, constants, names, previous, length, active, failure, clear_error)
        self.producer = producer
        self.producer_result = None
        self.in_producer, self.producer_calls = False, 0

    def store(self, ptr, width, value):
        super().store(ptr, width, value)
        base = self.producer_result
        if self.in_producer and ptr.region == base.region and base.offset <= ptr.offset < base.offset + 24:
            require(ptr.offset + width <= base.offset + 24, 'bounded actual producer result write')
            self.events.append(('result', ptr.offset - base.offset, width, value))

    def run(self, name, args, depth=0):
        if name == self.producer:
            require(not self.in_producer and self.producer_calls == 0 and len(args) == 6,
                    'exactly one actual bulk producer handoff')
            result = args[0]
            require(isinstance(result, model.Pointer) and result.region not in ('result', 'reader', 'storage', 'output')
                    and args[1:] == [model.Pointer('reader'), model.Pointer('output'), self.length, 0, model.UNKNOWN],
                    'original borrowed reader/output/length, byte mode and absent final-bit metadata')
            self.address(result, 24, access=False)
            self.producer_result = result
            self.producer_calls += 1
            self.events.append(('producer-enter',))
            self.in_producer = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.in_producer = False
                self.events.append(('producer-exit',))
        return super().run(name, args, depth)


def run(machine, root, length, active, composed):
    result = machine.allocate('result', 24)
    reader = machine.allocate('reader', 16)
    storage = machine.allocate('storage', 1040, payload=True)
    output = machine.allocate('output', length, payload=True)
    machine.fields(reader, [(0, 8, storage), (8, 1, active)])
    machine.events.clear()
    args = [result, reader, output, length] + ([] if composed else [0, model.UNKNOWN])
    try:
        require(machine.run(root, args) is None, 'void bulk result ABI')
    except model.Unwind as error:
        require(error.value == machine.exception, 'original bulk exception preserved')
        return True
    return False


def inspect(case, thorough=True, check_producer=True):
    # The independent producer oracle is checked first, before comparing traces.
    # Tests may reuse that check only while mutating outer forwarding functions.
    if check_producer:
        guard.inspect(case.inner, thorough)
    producer, names, merged = closure(case)
    functions, constants = guard.begin.functions_and_constants(case.inner, merged)
    count, visited = 0, set()
    for length, previous, active, failure, clear_error in guard.scenarios(names['rate'], thorough):
        args = (functions, constants, names, previous, length, active, failure, clear_error)
        machine = BulkGuard(*args, producer)
        reference = guard.GuardedSqueeze(*args)
        unwound = run(machine, case.outer.root, length, active, True)
        reference_unwind = run(reference, producer, length, active, False)
        require(unwound == reference_unwind and machine.producer_calls == 1, 'same single producer outcome')
        expected = [('producer-enter',)] + reference.events + [('producer-exit',)]
        if not unwound:
            tag = reference.load(model.Pointer('result'), 8)
            if tag == 2:
                error = reference.load(model.Pointer('result', 8), 1)
                mapped = (0, 3, 4, 4, 5)[error] + (12 if case.outer.enabled else 0)
                expected += [('result', 8, 1, mapped), ('result', 0, 8, 2)]
            else:
                require(tag == int(length != 0), 'exact empty/nonempty ownership result')
                if length:
                    expected += [('result', 8, 8, model.Pointer('output')), ('result', 16, 8, length)]
                expected += [('result', 0, 8, tag)]
        require(machine.events == expected, 'exact bulk producer/result/cleanup ordering: '
                + repr((length, previous, active, failure, clear_error)) + '; difference=' + repr(next(
                    ((i, a, b) for i, (a, b) in enumerate(zip(machine.events, expected)) if a != b),
                    ('lengths', len(machine.events), len(expected)))))
        require(machine.counter_bytes == reference.counter_bytes and machine.reads == reference.reads
                and machine.writes == reference.writes and machine.progress == reference.progress
                and machine.load(model.Pointer('reader'), 8) == model.Pointer('storage')
                and machine.load(model.Pointer('reader', 8), 1) == reference.load(model.Pointer('reader', 8), 1),
                'same counter/progress effects and success-only reusable original reader')
        visited.update(machine.visited)
        count += 1
    return count, merged, visited


def main(record, shard=None):
    before = comparison.capture.sources()
    selected = list(cases(record))
    require(len(selected) == 16 and (shard is None or shard in range(4)), 'sixteen paths and valid shard')
    chosen = selected if shard is None else selected[4 * shard:4 * shard + 4]
    counts = []
    for case in chosen:
        count, merged, _ = inspect(case)
        counts.append(count)
        print(f'Composed bulk path: {count} cases; {len(merged)} functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print('Composed bulk cases: ' + str(sum(counts)))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Fill/copy/volatile bodies opaque; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
