#!/usr/bin/env python3
"""Retained debug counter byte decoding, helper traversal and limit caller."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re

import check_debug_output_limit as limit

comparison, model, require = limit.comparison, limit.model, limit.require


@dataclass(frozen=True)
class PackedResult:
    """Known fields of an eight-byte ABI carrier; padding remains undefined."""
    fields: tuple


def closure(case):
    producer, names, _, guarded = limit.closure(case)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core', 'hash_core')}
    selected, owners, pending, panics = {}, {}, [(names['counter'], 'sha3')], set()
    intrinsics = {'llvm.memcpy.p0.p0.i64', 'llvm.uadd.with.overflow.i64', 'llvm.umul.with.overflow.i32'}
    while pending:
        name, source = pending.pop()
        if name in intrinsics:
            continue
        if re.search(r'24panic_const_(?:shl|add)_overflow', name):
            panics.add(name)
            continue
        if name not in artifacts[source]:
            matches = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(matches) == 1, 'unique defined counter dependency: ' + name)
            source = matches[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed counter/helper ABI')
        if name in selected:
            require(model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name]), 'identical shared iterator helper')
            continue
        selected[name], owners[name] = body, source
        pending.extend((callee, source) for callee in limit.bulk.calls(body))
    require(len(selected) == 12 and len(panics) == 2, 'twelve-function decoder with two forbidden panic boundaries')
    shifts = [name for name in selected if '10byte_shift' in name]
    require(len(shifts) == 1, 'one actual byte-shift helper')
    merged = dict(guarded)
    for name, body in selected.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'same composed decoder helper')
        merged[name] = body
    require(len(merged) == len(guarded) + 12, 'complete limit/decoder composition')
    return producer, dict(names, shift=shifts[0], panics=panics), selected, merged, owners


class CounterModel(limit.LimitModel):
    def __init__(self, functions, constants, names, counter, active=1, mode=0):
        super().__init__(functions, constants, names, counter, active, mode)
        self.counter_bytes = counter.to_bytes(16, 'little')
        self.decoding = False
        self.reads = []
        self.step_limit = 15000

    def load(self, ptr, width):
        if isinstance(ptr, model.Pointer) and ptr.region == 'storage':
            require(self.decoding and width == 1 and 16 <= ptr.offset < 32,
                    'decoder reads only original individual counter bytes')
            self.address(ptr, width, access=False)
            self.reads.append(ptr.offset - 16)
            return self.counter_bytes[ptr.offset - 16]
        if isinstance(ptr, model.Pointer) and ':' in ptr.region and width == 8:
            fields = self.local_fields(ptr, width)
            shape = {(offset, size) for offset, size, _ in fields}
            if shape in ({(0, 1), (4, 4)}, {(0, 1), (1, 1)}):
                return PackedResult(tuple(fields))
        return super().load(ptr, width)

    def local_fields(self, ptr, width):
        self.address(ptr, width)
        require(':' in ptr.region, 'compiler-local ABI storage only')
        fields = [(other.offset - ptr.offset, size, value) for other, (size, value) in self.memory.items()
                  if other.region == ptr.region and ptr.offset <= other.offset < ptr.offset + width]
        require(all(offset + size <= width for offset, size, _ in fields), 'whole local ABI fields')
        return fields

    def store(self, ptr, width, value):
        if isinstance(value, PackedResult):
            require(width == 8 and ':' in ptr.region, 'packed result only moves through local eight-byte storage')
            super().store(ptr, width, model.UNKNOWN)
            for offset, size, field in value.fields:
                super().store(model.Pointer(ptr.region, ptr.offset + offset), size, field)
            return
        super().store(ptr, width, value)

    def run(self, name, args, depth=0):
        if name == 'llvm.memcpy.p0.p0.i64' and len(args) == 4 and args[2] == 8:
            destination, source, _, volatile = args
            require(volatile == 0 and isinstance(source, model.Pointer) and isinstance(destination, model.Pointer)
                    and source.region != destination.region and ':' in destination.region,
                    'nonoverlapping nonvolatile local result-ABI copy')
            fields = self.local_fields(source, 8)
            super().store(destination, 8, model.UNKNOWN)
            self.fields(destination, fields)
            return None
        if name in self.names['panics']:
            raise ValueError('counter decoder must not panic for bounded iteration')
        if name == self.names['counter']:
            require(args == [model.Pointer('storage', 16)] and not self.decoding, 'original borrowed counter; no recursive decoding')
            self.events.append(('counter-read',))
            self.decoding = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.decoding = False
        return super().run(name, args, depth)


def values(thorough):
    basis = [0, limit.MAXIMUM, int.from_bytes(bytes(range(16)), 'little'),
             int.from_bytes(bytes(reversed(range(16))), 'little')]
    basis += [1 << bit for bit in range(128)] if thorough else [1 << (8 * index) for index in range(16)]
    return basis


def inspect(case, thorough=True):
    producer, names, selected, merged, owners = closure(case)
    functions, constants = limit.begin.functions_and_constants(case, merged)
    count, visited = 0, set()
    for value in values(thorough):
        machine = CounterModel(functions, constants, names, value)
        machine.allocate('storage', 1040, payload=True)
        require(machine.run(names['counter'], [model.Pointer('storage', 16)]) == value, 'exact little-endian full-width counter')
        require(machine.reads == list(range(16)) and machine.events == [('counter-read',)],
                'each original byte once, in order, with no owner mutation')
        visited.update(machine.visited)
        count += 1
    # Test the actual enclosing limit adapter on both sides of each overflow boundary.
    for value in limit.values(thorough):
        for increment in sorted({0, 1, limit.MAXIMUM - value, min(limit.MAXIMUM, limit.MAXIMUM - value + 1)}):
            machine = CounterModel(functions, constants, names, value)
            owner = machine.allocate('storage', 1040, payload=True)
            require(machine.run(names['empty_check'], [owner, increment]) == int(value + increment > limit.MAXIMUM),
                    'actual decoder result feeds exact limit decision')
            require(machine.reads == list(range(16)) and machine.events == [('counter-read',)], 'unchanged borrowed counter')
            count += 1
        for active in (0, 1):
            for mode in (0, 1):
                machine = CounterModel(functions, constants, names, value, active, mode)
                result = machine.allocate('result', 24)
                reader = machine.allocate('reader', 16)
                storage = machine.allocate('storage', 1040, payload=True)
                output = machine.allocate('output', 0, payload=True)
                machine.fields(reader, [(0, 8, storage), (8, 1, active)])
                machine.events.clear()
                require(machine.run(producer, [result, reader, output, 0, mode, machine.valid]) is None, 'empty producer returns')
                expected = [('begin',)] + ([('reader', 8, 1, 0), ('operation',), ('counter-read',), ('finish',),
                            ('reader', 8, 1, 1), ('result', 0, 8, 0)] if active else
                            [('result', 8, 1, 0), ('result', 0, 8, 2)])
                require(machine.events == expected and machine.reads == (list(range(16)) if active else []),
                        'composed original counter admission and terminal-state exclusion')
                require(machine.load(reader, 8) == storage and machine.load(model.Pointer('reader', 8), 1) == active,
                        'unchanged reader owner and successful active state')
                count += 1
    # Conversion/multiplication fallback paths are unreachable for a real 16-byte
    # iterator but checked independently, without pretending they are runtime inputs.
    for offset in (*range(16), (1 << 29) - 1, 1 << 29, (1 << 32) - 1, 1 << 32, model.MASK):
        machine = CounterModel(functions, constants, names, 0)
        expected = offset * 8 if offset < 1 << 29 else 0
        require(machine.run(names['shift'], [offset]) == expected, 'exact checked offset conversion/multiplication or zero default')
        visited.update(machine.visited)
        count += 1
    # Exclude blocks reachable only through the two explicitly forbidden panic
    # boundaries, plus blocks with no entry path. Do not infer coverage by label.
    for name, body in selected.items():
        graph = model.blocks(body)
        reachable, pending = set(), ['start']
        while pending:
            label = pending.pop()
            require(label in graph, 'defined counter helper successor')
            if label in reachable or any(panic in line for panic in names['panics'] for line in graph[label]):
                continue
            require(graph[label] != ['unreachable'], 'no reachable unqualified unreachable block')
            reachable.add(label)
            pending.extend(re.findall(r'label %(\S+?)(?:,|\s|$)', '\n'.join(graph[label])))
        require({label for function, label in visited if function == name} == reachable,
                'all decoder/helper normal blocks covered; panic paths excluded')
    return count, selected, merged, visited


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in limit.begin.guard.final.cases(record)]
    require(len(results) == 16 and all(count == 237 for count, _, _, _ in results)
            and before == comparison.capture.sources(), 'complete unchanged decoder matrix')
    print('Debug counter decode: ' + repr([(count, len(merged)) for count, _, merged, _ in results]) + ' PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Scalar-copy/register/spill cleanup not established; squeeze/volatile bodies opaque; no rebuild/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
