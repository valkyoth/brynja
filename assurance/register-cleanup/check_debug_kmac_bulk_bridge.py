#!/usr/bin/env python3
"""Retained debug KMAC bulk reader forwarding/result ownership; no producer proof."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re

import check_kmac_verify_comparisons as comparison
import debug_write_model as model

require = comparison.require


@dataclass(frozen=True)
class Case:
    root: str
    kmac: str
    sha3: str
    accelerated: bool
    enabled: bool


def calls(body):
    for lines in model.blocks(body).values():
        for line in lines:
            if re.search(r'\b(?:call|invoke) ', line):
                match = re.search(comparison.SYMBOL, line)
                require(match is not None, 'direct debug bridge dependency')
                yield match[1]


def cases(record):
    for row, kmac, _, _ in comparison.cases(record):
        if row['profile'] != 'debug':
            continue
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'same-configuration SHA-3 artifact')
        sha3 = paths[0].read_text()
        enabled = row['mode'] == 'accelerated'
        roots = []
        for caller in comparison.verifiers(kmac, enabled):
            names = [name for name in calls(caller)
                     if 'brynja_mac_kmac' in name and 'Reader' in name
                     and re.search(r'6secret(?:17h[0-9a-f]+E"?)?$', name)]
            require(len(names) == 1, 'one actual debug verifier bulk bridge')
            roots.extend(names)
        require(len(set(roots)) == len(roots), 'distinct instantiated debug bulk bridges')
        for root in roots:
            yield Case(root, kmac, sha3, 'accelerated' in root, enabled)


def abi(body, count):
    header = body.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    require(symbol is not None and header.startswith('define internal void @' if count == 6 else 'define void @'),
            'defined void bridge ABI')
    args = comparison.arguments(header, symbol.end())
    require(len(args) == count and args[0] == 'ptr sret([24 x i8]) align 8 %_0',
            'complete original output-result descriptor ABI')
    for index in (1, 2):
        comparison.pointer(args[index])
    require(args[3].startswith('i64 %'), 'original 64-bit destination length')
    if count == 6:
        require(args[4] == 'i1 zeroext %0' and args[5] == 'i8 %1',
                'producer final-mode and bit-tail ABI')


def closure(case):
    kmac, sha3 = comparison.definitions(case.kmac), comparison.definitions(case.sha3)
    require(case.root in kmac, 'actual debug KMAC bridge definition')
    root = kmac[case.root]
    abi(root, 4)
    require(model.parameters(root) == ['%_0', '%self', '%output.0', '%output.1'], 'bulk bridge parameters')
    entries = [name for name in calls(root) if '14squeeze_secret' in name]
    require(len(entries) == 1 and entries[0] in sha3, 'actual same-row SHA-3 reader')
    entry = entries[0]
    require(('accelerated' in entry) == case.accelerated
            and ('Cshake128Reader' in entry) == ('Cshake128Reader' in case.root)
            and ('Cshake256Reader' in entry) == ('Cshake256Reader' in case.root), 'exact family and identity')
    abi(sha3[entry], 4)
    producers = list(calls(sha3[entry]))
    require(len(producers) == 1 and producers[0] in sha3 and 'Borrowed' in producers[0]
            and '6secret' in producers[0], 'one defined borrowed producer boundary')
    producer = producers[0]
    require(('accelerated' in producer) == case.accelerated, 'unchanged selected producer family')
    # The producer body is not interpreted here; it is an explicit opaque
    # boundary. Bind its actual ABI, not a same-spelled declaration or alias.
    abi(sha3[producer], 6)
    definitions = dict(kmac)
    definitions[entry] = sha3[entry]
    pending, selected = [case.root], {}
    while pending:
        name = pending.pop()
        if name in selected or name in (producer, 'llvm.memcpy.p0.p0.i64'):
            continue
        require(name in definitions, 'bound debug bridge helper: ' + name)
        selected[name] = definitions[name]
        require(not re.search(r'\b(?:byval|inalloca)\b', definitions[name]), 'no by-value borrowed descriptor ABI')
        pending.extend(calls(definitions[name]))
    require(len(selected) == 5, 'bridge, reader, result mapper, adapter and error conversion')
    return producer, selected


class BridgeModel(model.Model):
    def __init__(self, functions, producer, length, error, unwind):
        super().__init__(functions, '', '')
        self.producer, self.length, self.error, self.unwind = producer, length, error, unwind
        self.exception = (model.Pointer('exception', 7), 19)
        self.output_writes = []

    def store(self, ptr, width, value):
        super().store(ptr, width, value)
        if ptr.region == 'result':
            self.output_writes.append((ptr.offset, width, value))

    def run(self, name, args, depth=0):
        if name == self.producer:
            require(len(args) == 6 and args[1:] == [model.Pointer('reader'), model.Pointer('output'),
                    self.length, 0, model.UNKNOWN], 'unchanged owner/destination/length, bulk mode only')
            self.address(args[0], 24)
            self.events.append(('producer',))
            if self.unwind:
                raise model.Unwind(self.exception)
            if self.error is not None:
                self.store(args[0], 8, 2)
                self.store(model.Pointer(args[0].region, args[0].offset + 8), 1, self.error)
            else:
                self.store(args[0], 8, int(self.length != 0))
                self.store(model.Pointer(args[0].region, args[0].offset + 8), 8, model.Pointer('output'))
                self.store(model.Pointer(args[0].region, args[0].offset + 16), 8, self.length)
            return None
        if name == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[2:] == [24, 0], 'complete nonvolatile ownership-descriptor move')
            destination, source = args[:2]
            self.address(source, 24)
            self.address(destination, 24)
            require(source.region != destination.region, 'nonoverlapping descriptor copy')
            # Only metadata is modeled. Any copy involving the protected reader
            # or payload allocation fails address(); no payload byte is read.
            values = [(ptr.offset - source.offset, width, value)
                      for ptr, (width, value) in self.memory.items()
                      if ptr.region == source.region and source.offset <= ptr.offset < source.offset + 24]
            require(all(offset + width <= 24 for offset, width, _ in values), 'whole typed descriptor fields')
            for offset, width, value in values:
                self.store(model.Pointer(destination.region, destination.offset + offset), width, value)
            self.events.append(('descriptor',))
            return None
        return super().run(name, args, depth)


def inspect(case):
    producer, selected = closure(case)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in selected.items()}
    errors = range(12) if case.accelerated else range(5)
    count, visited = 0, set()
    for length in (0, 1, 7, 168, 169, 4096, (1 << 63) - 1):
        for error, unwind in [(None, False), (None, True)] + [(value, False) for value in errors]:
            machine = BridgeModel(functions, producer, length, error, unwind)
            result = machine.allocate('result', 24)
            reader = machine.allocate('reader', 16, payload=True)
            output = machine.allocate('output', length, payload=True)
            try:
                require(machine.run(case.root, [result, reader, output, length]) is None, 'void bridge result')
            except model.Unwind as failure:
                require(unwind and failure.value == machine.exception, 'original producer unwind propagates')
            else:
                require(not unwind, 'producer exception must not be swallowed')
            expected = [('producer',)] + ([] if error is not None or unwind else [('descriptor',)] * 2)
            require(machine.events == expected, 'one producer call then descriptor-only result transfer')
            writes = machine.output_writes
            if unwind:
                require(writes == [], 'no output-result publication on unwind')
            elif error is None:
                require(writes == [(0, 8, int(length != 0)), (8, 8, output), (16, 8, length)],
                        'original empty/nonempty secret-output ownership preserved')
            else:
                converted = error if case.accelerated else (0, 3, 4, 4, 5)[error] + (12 if case.enabled else 0)
                require(writes == [(8, 1, converted), (0, 8, 2)], 'exact failure mapping; never success or fallback')
            visited.update(machine.visited)
            count += 1
    expected_blocks = {(name, label) for name, (_, graph) in functions.items()
                       for label, lines in graph.items() if lines != ['unreachable']}
    require(visited == expected_blocks, 'all reachable bridge/reader/error-helper blocks inspected')
    return count


def main(record):
    before = comparison.capture.sources()
    selected = list(cases(record))
    count = sum(inspect(case) for case in selected)
    require(len(selected) == 24 and count == 1568 and before == comparison.capture.sources(),
            'unchanged complete debug bulk matrix')
    print(f'Debug KMAC bulk bridges: {len(selected)} five-function closures; {count} result/unwind cases PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Borrowed producer opaque: no reader-internal cleanup, consuming-final path, whole verifier, spill or native-platform proof; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
