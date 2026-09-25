#!/usr/bin/env python3
"""Compose accelerated bulk/consuming reader bridges with checked output operations."""
import argparse
import json
from pathlib import Path
import re

import check_debug_accelerated_operation as operation

model, require, comparison = operation.model, operation.require, operation.comparison
bulk, final = operation.bulk, operation.guard.final


def bulk_case(case):
    roots = [name for caller in comparison.verifiers(case.kmac, True) for name in bulk.calls(caller)
             if 'brynja_mac_kmac' in name and 'Reader' in name and 'accelerated' in name
             and re.search(r'6secret(?:17h[0-9a-f]+E"?)?$', name)
             and ('Cshake128Reader' in name) == ('Cshake128Reader' in case.root)
             and ('Cshake256Reader' in name) == ('Cshake256Reader' in case.root)]
    require(len(roots) == 1, 'same-row same-strength accelerated bulk reader')
    return bulk.Case(roots[0], case.kmac, case.sha3, True, True)


def closure(case, consuming):
    producer, names, merged = operation.closure(case)
    if consuming:
        outer_producer, wipe, outer = final.closure(case)
        require(wipe == names['wipe'], 'same consuming clearing primitive')
        root = case.root
    else:
        outer_case = bulk_case(case)
        outer_producer, outer = bulk.closure(outer_case)
        root = outer_case.root
    require(producer == outer_producer, 'outer reader invokes the actual checked producer')
    for name, body in outer.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical bridge/producer helper')
        merged[name] = body
    return root, producer, names, outer, merged


class BridgedOperation(operation.OperationModel):
    def __init__(self, functions, constants, names, length, mode, valid, failure, producer):
        super().__init__(functions, constants, names, length, mode, valid, failure)
        self.producer = producer
        self.reader_address = self.producer_result = None
        self.in_producer, self.producer_calls = False, 0

    def store(self, ptr, width, value):
        super().store(ptr, width, value)
        base = self.producer_result
        if self.in_producer and ptr.region == base.region and base.offset <= ptr.offset < base.offset + 24:
            require(ptr.offset + width <= base.offset + 24, 'bounded actual producer-result write')
            self.events.append(('result', ptr.offset - base.offset, width, value))

    def run(self, name, args, depth=0):
        if name == 'llvm.memcpy.p0.p0.i64' and not self.in_producer:
            require(len(args) == 4 and args[2:] == [24, 0], 'whole nonvolatile outer result descriptor')
            value = super().run(name, args, depth)
            self.events.append(('outer-descriptor',))
            return value
        if name == self.producer:
            require(not self.in_producer and self.producer_calls == 0 and len(args) == 6,
                    'one nonrecursive actual reader/producer handoff')
            result, reader = args[:2]
            require(isinstance(result, model.Pointer) and isinstance(reader, model.Pointer)
                    and result.region not in ('result', 'entry-reader', 'storage', 'output')
                    and args[2:] == [model.Pointer('output'), self.length, self.mode, self.valid],
                    'original output and exact bulk/final shape to compiler-local result')
            require((reader.region not in ('result', 'entry-reader', 'storage', 'output') if self.mode
                     else reader == model.Pointer('entry-reader'))
                    and self.load(reader, 8) == model.Pointer('storage'), 'original reader borrows original storage')
            self.address(result, 24)
            self.address(reader, 8)
            self.reader_address, self.producer_result = reader, result
            self.producer_calls += 1
            self.in_producer = True
            self.events.append(('producer-enter',))
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.in_producer = False
                self.events.append(('producer-exit',))
        if name == self.names['guard']:
            require(self.in_producer and not self.in_guard and len(args) == 3
                    and args[1] == self.reader_address and self.load(args[1], 8) == model.Pointer('storage'),
                    'guard binds actual original reader, never a replacement descriptor')
            self.guard_pointer = model.Pointer(f'{self.frames + 1}:%guard')
            self.in_guard = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.in_guard = False
        return super().run(name, args, depth)


def scenarios(thorough, consuming):
    for length, mode, valid, failure in operation.scenarios(thorough):
        if mode == int(consuming) and (consuming or valid is model.UNKNOWN):
            yield length, mode, valid, failure


def inspect(case, thorough=True, consuming=True):
    root, producer, names, outer, merged = closure(case, consuming)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in merged.items()}
    constants = '\n'.join(dict.fromkeys(line for text in (case.sha3, case.core, case.hash_core, case.kmac)
                                      for line in text.splitlines() if line.startswith(('@anon.', '@alloc_'))))
    cleanup = [('state', 859, 1, 1), ('state', 616, 8, 0)] + [
        ('wipe', 'storage', offset, width) for offset, width in ((656, 200), (624, 16), (640, 16), (856, 2), (864, 168), (1056, 2))]
    count, visited = 0, set()
    for length, mode, valid, failure in scenarios(thorough, consuming):
        machine = BridgedOperation(functions, constants, names, length, mode, valid, failure, producer)
        result = machine.allocate('result', 24)
        reader = machine.allocate('entry-reader', 8)
        storage = machine.allocate('storage', 1088, payload=True)
        output = machine.allocate('output', length, payload=True)
        machine.fields(reader, [(0, 8, storage)])
        machine.events.clear()
        unwound = False
        try:
            require(machine.run(root, [result, reader, output, length] + ([valid] if consuming else [])) is None, 'void actual reader bridge')
        except model.Unwind as error:
            require(error.value == machine.exception, 'original exception through outer reader')
            unwound = True
        inner, progress, success = operation.expected(length, mode, valid, failure)
        expected = [('producer-enter',)] + inner + [('producer-exit',)] + (cleanup if consuming else [])
        if not unwound:
            if success:
                fields = ((8, 8, output), (16, 8, length), (0, 8, 1)) if length else ((0, 8, 0),)
                expected += [('outer-descriptor',)] + [('result', *field) for field in fields] + [('outer-descriptor',)]
            else:
                errors = [event[3] for event in inner if event[:3] == ('result', 8, 1)]
                require(len(errors) == 1, 'one independent producer error identity')
                expected += [('result', 8, 1, errors[0]), ('result', 0, 8, 2)]
        require(machine.events == expected, 'exact composed bridge/operation/cleanup trace: '
                + repr((consuming, length, valid, failure)) + '; difference=' + repr(next(
                    ((i, a, b) for i, (a, b) in enumerate(zip(machine.events, expected)) if a != b),
                    ('lengths', len(machine.events), len(expected)))))
        require(unwound == (failure is not None and failure[2] == 'unwind') and machine.progress == progress
                and machine.producer_calls == 1 and not machine.in_producer and not machine.in_guard
                and not machine.inside_operation and 'reader' not in machine.sizes
                and machine.load(machine.reader_address, 8) == storage and machine.load(reader, 8) == storage
                and machine.guard_stores == ([] if failure and failure[0] == 'clear' else [0, 1] if success else [0]),
                'original reader/owner, single producer, exact progress and success-only local-guard completion')
        visited.update(machine.visited)
        count += 1
    for name, body in outer.items():
        if name not in (root,) and 'squeeze' not in name:
            continue
        for label, lines in model.blocks(body).items():
            if lines == ['unreachable'] or any('16panic_in_cleanup' in line for line in lines):
                continue
            require((name, label) in visited, 'all selected outer reader entry/error/unwind blocks exercised')
    return count, merged, visited


def main(record, shard):
    before = comparison.capture.sources()
    cases = list(operation.cases(record))
    require(len(cases) == 8, 'eight accelerated debug compiler/target/strength paths')
    for case in cases if shard is None else [cases[shard]]:
        for consuming in (False, True):
            count, merged, _ = inspect(case, consuming=consuming)
            print(f'Accelerated {"consuming" if consuming else "bulk"} bridge: {count} cases; {len(merged)} functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all 8 paths, both bridges' if shard is None else f'shard {shard}/8; both bridges; all eight required'))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Engine/primitive bodies opaque; no whole-verifier/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
