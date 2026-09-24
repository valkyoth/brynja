#!/usr/bin/env python3
"""Retained debug counter writer, actual decoder round-trip and squeeze binding."""
import argparse
import json
from pathlib import Path
import re

import check_debug_counter_decode as decode

comparison, model, require = decode.comparison, decode.model, decode.require


def closure(case):
    _, names, decoded, guarded, _ = decode.closure(case)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core', 'hash_core')}
    squeeze = artifacts['sha3'][names['squeeze']]
    writers = [name for name in decode.limit.bulk.calls(squeeze) if '13write_counter' in name]
    require(len(writers) == 1, 'one writer selected from actual byte-squeeze body')
    writer = writers[0]
    require(writer in artifacts['sha3'], 'defined same-configuration counter writer')
    header = artifacts['sha3'][writer].splitlines()[0]
    args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    require(header.startswith('define void @') and len(args) == 2
            and comparison.pointer(args[0]) == '%bytes' and args[1] == 'i128 %value', 'borrowed writer ABI')
    selected, pending, panics = {}, [(writer, 'sha3')], set()
    intrinsics = {'llvm.memcpy.p0.p0.i64', 'llvm.uadd.with.overflow.i64', 'llvm.umul.with.overflow.i32'}
    while pending:
        name, source = pending.pop()
        if name in intrinsics:
            continue
        if re.search(r'24panic_const_(?:shr|add)_overflow', name):
            panics.add(name)
            continue
        if name not in artifacts[source]:
            matches = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(matches) == 1, 'unique defined writer dependency: ' + name)
            source = matches[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed writer/helper ABI')
        if name in selected:
            require(model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name]), 'identical shared writer helper')
            continue
        selected[name] = body
        pending.extend((callee, source) for callee in decode.limit.bulk.calls(body))
    require(len(selected) == 14 and len(panics) == 2, 'fourteen-function writer with two forbidden panic boundaries')
    narrowing = [name for name, body in selected.items() if '8try_from' in name and model.parameters(body) == ['%u']
                 and '(i128 %u)' in body.splitlines()[0]]
    defaults = [name for name, body in selected.items() if '17unwrap_or_default' in name and body.startswith('define i8 @')]
    require(len(narrowing) == len(defaults) == 1, 'actual narrowing and default helpers')
    merged = dict(guarded)
    for name, body in selected.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical decoder/writer shared helpers')
        merged[name] = body
    require(len(set(selected) & set(decoded)) == 5 and len(merged) == len(guarded) + 9,
            'five shared helpers and nine newly bound writer helpers')
    return dict(names, writer=writer, narrow=narrowing[0], default=defaults[0], panics=names['panics'] | panics), selected, merged


class WriterModel(decode.CounterModel):
    def __init__(self, functions, constants, names, previous):
        super().__init__(functions, constants, names, previous)
        self.counter_bytes = bytearray(self.counter_bytes)
        self.writing = False
        self.writes = []
        self.step_limit = 30000

    def store(self, ptr, width, value):
        if isinstance(ptr, model.Pointer) and ptr.region == 'storage':
            require(self.writing and width == 1 and 16 <= ptr.offset < 32 and type(value) is int and 0 <= value <= 255,
                    'writer changes only original individual output-counter bytes')
            self.address(ptr, width, access=False)
            self.counter_bytes[ptr.offset - 16] = value
            self.writes.append((ptr.offset - 16, value))
            return
        return super().store(ptr, width, value)

    def run(self, name, args, depth=0):
        if name == self.names['writer']:
            require(len(args) == 2 and args[0] == model.Pointer('storage', 16)
                    and type(args[1]) is int and 0 <= args[1] <= decode.limit.MAXIMUM
                    and not self.writing and not self.decoding, 'original writer field and valid u128 input')
            self.events.append(('counter-write',))
            self.writing = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.writing = False
        return super().run(name, args, depth)


def inspect(case, thorough=True):
    names, selected, merged = closure(case)
    functions, constants = decode.limit.begin.functions_and_constants(case, merged)
    count, visited = 0, set()
    for value in decode.values(thorough):
        # Every starting byte is guaranteed wrong, so skipped/partial writes
        # cannot pass by reusing a previous expected result.
        machine = WriterModel(functions, constants, names, value ^ decode.limit.MAXIMUM)
        machine.allocate('storage', 1040, payload=True)
        require(machine.run(names['writer'], [model.Pointer('storage', 16), value]) is None, 'void actual writer')
        expected = list(value.to_bytes(16, 'little'))
        require(machine.writes == list(enumerate(expected)) and list(machine.counter_bytes) == expected,
                'exact sixteen original bytes written once, in order')
        require(not machine.reads and machine.events == [('counter-write',)], 'writer does not read old counter or touch other owners')
        require(machine.run(names['counter'], [model.Pointer('storage', 16)]) == value, 'actual decoder round-trip')
        require(machine.reads == list(range(16)) and machine.events == [('counter-write',), ('counter-read',)],
                'one exact readback and no extra mutation')
        visited.update(machine.visited)
        count += 1
    for value in (*range(256), 256, 257, decode.limit.MAXIMUM - 1, decode.limit.MAXIMUM) if thorough else (
            0, 1, 127, 128, 254, 255, 256, 257, decode.limit.MAXIMUM):
        machine = WriterModel(functions, constants, names, 0)
        result = machine.run(names['narrow'], [value])
        require(isinstance(result, tuple) and len(result) == 2 and result[0] == int(value > 255), 'checked byte conversion tag')
        if value <= 255:
            require(result[1] == value, 'exact byte conversion value')
        require(machine.run(names['default'], list(result)) == (value if value <= 255 else 0), 'exact conversion default')
        require(not machine.events and not machine.writes and not machine.reads, 'scalar helper has no owner effects')
        visited.update(machine.visited)
        count += 1
    # Reuse the shared byte-shift helper checks at conversion/multiplication boundaries.
    for offset in (*range(16), (1 << 29) - 1, 1 << 29, (1 << 32) - 1, 1 << 32, model.MASK):
        machine = WriterModel(functions, constants, names, 0)
        require(machine.run(names['shift'], [offset]) == (offset * 8 if offset < 1 << 29 else 0), 'checked byte shift/default')
        visited.update(machine.visited)
        count += 1
    for name, body in selected.items():
        graph = model.blocks(body)
        reachable, pending = set(), ['start']
        while pending:
            label = pending.pop()
            require(label in graph, 'defined writer helper successor')
            if label in reachable or any(panic in line for panic in names['panics'] for line in graph[label]):
                continue
            require(graph[label] != ['unreachable'], 'no reachable unqualified unreachable block')
            reachable.add(label)
            pending.extend(re.findall(r'label %(\S+?)(?:,|\s|$)', '\n'.join(graph[label])))
        require({label for function, label in visited if function == name} == reachable,
                'all writer/helper normal blocks covered; panic paths excluded')
    return count, selected, merged, visited


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in decode.limit.begin.guard.final.cases(record)]
    require(len(results) == 16 and all(count == 413 for count, _, _, _ in results)
            and before == comparison.capture.sources(), 'complete unchanged writer matrix')
    print('Debug counter write: ' + repr([(count, len(merged)) for count, _, merged, _ in results]) + ' PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Actual squeeze selects this writer, but its execution/commit ordering remains unmodeled; no scalar/spill/native erasure proof')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
