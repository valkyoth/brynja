#!/usr/bin/env python3
"""Retained accelerated debug final bridge and consuming owned-clear requests."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re

import check_debug_kmac_bulk_bridge as bulk

comparison, model, require = bulk.comparison, bulk.model, bulk.require


@dataclass(frozen=True)
class Case:
    root: str
    kmac: str
    sha3: str
    core: str
    compiler: str


def cases(record):
    for row, kmac, core, _ in comparison.cases(record):
        if row['profile'] != 'debug' or row['mode'] != 'accelerated':
            continue
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'same-configuration debug SHA-3 artifact')
        sha3 = paths[0].read_text()
        roots = []
        for caller in comparison.verifiers(kmac, True):
            names = [name for name in bulk.calls(caller) if 'accelerated' in name
                     and 'Reader' in name and re.search(r'12final_secret(?:17h[0-9a-f]+E"?)?$', name)]
            require(len(names) <= 1, 'unique accelerated debug final bridge')
            roots.extend(names)
        require(len(roots) == len(set(roots)) == 2, 'both accelerated final reader strengths')
        for root in roots:
            yield Case(root, kmac, sha3, core, '1.90.0' if '1.90.0' in row['compiler'] else '1.98.1')


def closure(case):
    kmac, sha3, core = (comparison.definitions(text) for text in (case.kmac, case.sha3, case.core))
    require(case.root in kmac, 'actual final trait bridge')
    bulk.abi(kmac[case.root], 5)
    require('i8 %valid)' in kmac[case.root].splitlines()[0], 'byte-sized original final shape')
    require(model.parameters(kmac[case.root]) == ['%_0', '%self', '%output.0', '%output.1', '%valid'],
            'original final bridge arguments')
    entry = [name for name in bulk.calls(kmac[case.root]) if '25squeeze_final_bits_secret' in name]
    require(len(entry) == 1 and entry[0] in sha3, 'defined same-row final reader entry')
    entry = entry[0]
    require('accelerated' in entry and ('Cshake128Reader' in entry) == ('Cshake128Reader' in case.root)
            and ('Cshake256Reader' in entry) == ('Cshake256Reader' in case.root), 'exact final reader identity')
    bulk.abi(sha3[entry], 5)
    require('i8 %valid_bits)' in sha3[entry].splitlines()[0], 'byte-sized reader final shape')
    require(model.parameters(sha3[entry]) == ['%_0', '%0', '%output.0', '%output.1', '%valid_bits'],
            'consuming storage and original output shape')
    producers = [name for name in bulk.calls(sha3[entry]) if 'Borrowed' in name and '6secret' in name]
    require(len(producers) == 1 and producers[0] in sha3 and 'accelerated' in producers[0],
            'defined accelerated borrowed producer')
    producer = producers[0]
    bulk.abi(sha3[producer], 6)
    artifacts = {'kmac': kmac, 'sha3': sha3, 'core': core}
    pending, selected, excluded = [(case.root, 'kmac')], {}, set()
    owners = {}
    wipes = set()
    while pending:
        name, source = pending.pop()
        if name in excluded or name in (producer, 'llvm.memcpy.p0.p0.i64'):
            continue
        if '16panic_in_cleanup' in name:
            excluded.add(name)
            continue
        if name == entry:
            source = 'sha3'
        elif 'brynja_core' in name:
            source = 'core'
        require(name in artifacts[source], 'helper defined in its actual caller artifact: ' + name)
        if name in selected:
            require(owners[name] == source, 'unambiguous same-artifact helper binding')
            continue
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed final bridge dependencies')
        if 'secret_memory_volatile23zeroize_region_volatile' in name:
            header = body.splitlines()[0]
            args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
            require(header.startswith('define internal void @') and len(args) == 2
                    and comparison.pointer(args[0]) == '%region.0' and args[1] == 'i64 %region.1',
                    'actual borrowed volatile primitive ABI')
            wipes.add(name)
            excluded.add(name)
            continue
        selected[name] = body
        owners[name] = source
        pending.extend((callee, source) for callee in bulk.calls(body))
    require(len(selected) == 14 and len(wipes) == 1 and len(excluded) == 2,
            'fourteen-function final handoff/drop/clear closure plus volatile and double-panic boundaries')
    return producer, wipes.pop(), selected


class FinalModel(bulk.BridgeModel):
    def __init__(self, functions, producer, wipe, length, valid, error, unwind):
        super().__init__(functions, producer, length, error, unwind)
        self.wipe, self.valid = wipe, valid

    def load(self, ptr, width):
        require(isinstance(ptr, model.Pointer) and ptr.region != 'storage', 'no secret-state reads in final bridge or cleanup')
        return super().load(ptr, width)

    def store(self, ptr, width, value):
        require(isinstance(ptr, model.Pointer), 'known final handoff store address')
        if ptr.region == 'storage':
            require((ptr.offset, width, value) in ((859, 1, 1), (616, 8, 0)), 'terminal metadata stores only')
            self.events.append(('state', ptr.offset, width, value))
        super().store(ptr, width, value)
        if ptr.region == 'result':
            self.events.append(('result', ptr.offset, width, value))

    def run(self, name, args, depth=0):
        if name == self.producer:
            require(len(args) == 6 and self.load(args[1], 8) == model.Pointer('storage')
                    and args[2:] == [model.Pointer('output'), self.length, 1, self.valid],
                    'original consuming owner/output/length/valid bits, final mode')
            # Reuse only the existing opaque result injector, after validating
            # this final ABI. Bulk mode is not executed by the retained program.
            return super().run(name, [args[0], model.Pointer('reader'), args[2], args[3], 0, model.UNKNOWN], depth)
        if name == self.wipe:
            require(len(args) == 2 and isinstance(args[0], model.Pointer)
                    and type(args[1]) is int and args[0].region == 'storage',
                    'original live storage clear request')
            self.address(args[0], args[1], access=False)
            self.events.append(('wipe', args[0].offset, args[1]))
            return None
        return super().run(name, args, depth)


def inspect(case, thorough=True):
    producer, wipe, selected = closure(case)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in selected.items()}
    count, visited = 0, set()
    lengths = (0, 1, 167, 168, 169, 4096, (1 << 63) - 1) if thorough else (0, 169)
    valids = (0, 1, 7, 8, 9, 255) if thorough else (0, 7, 255)
    cleanup = [('state', 859, 1, 1), ('state', 616, 8, 0)] + [
        ('wipe', offset, length) for offset, length in ((656, 200), (624, 16), (640, 16),
                                                       (856, 2), (864, 168), (1056, 2))]
    for length in lengths:
        for valid in valids:
            for error, unwind in [(None, False), (None, True)] + [(value, False) for value in range(12)]:
                machine = FinalModel(functions, producer, wipe, length, valid, error, unwind)
                result = machine.allocate('result', 24)
                reader = machine.allocate('reader', 8)
                storage = machine.allocate('storage', 1088)
                output = machine.allocate('output', length, payload=True)
                machine.store(reader, 8, storage)
                try:
                    require(machine.run(case.root, [result, reader, output, length, valid]) is None, 'void final handoff')
                except model.Unwind as failure:
                    require(unwind and failure.value == machine.exception, 'resume original producer exception')
                else:
                    require(not unwind, 'producer unwind cannot be swallowed')
                expected = [('producer',)] + cleanup
                if not unwind:
                    if error is None:
                        expected += [('descriptor',)] + [('result', *item) for item in
                            ((0, 8, int(length != 0)), (8, 8, output), (16, 8, length))] + [('descriptor',)]
                    else:
                        expected += [('result', 8, 1, error), ('result', 0, 8, 2)]
                require(machine.events == expected, 'one complete consuming cleanup before exact result handoff or unwind')
                visited.update(machine.visited)
                count += 1
    # All six requested regions are nonempty. The core wrapper's empty-input
    # branch and cleanup-double-panic block are outside these caller paths.
    expected = set()
    for name, (_, graph) in functions.items():
        for label, lines in graph.items():
            if lines == ['unreachable'] or any('16panic_in_cleanup' in line for line in lines):
                continue
            if 'secret_memory18clear_owned_region' in name and any(line.startswith('store i8 0,') for line in lines):
                continue
            expected.add((name, label))
    require(visited == expected, 'all selected normal/nonempty/error/unwind blocks visited')
    return count


def main(record):
    before = comparison.capture.sources()
    selected = list(cases(record))
    count = sum(inspect(case) for case in selected)
    require(len(selected) == 8 and count == 4704 and before == comparison.capture.sources(),
            'unchanged complete accelerated debug final matrix')
    print(f'Debug accelerated final bridges: {len(selected)} fourteen-function closures; {count} result/unwind cases PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Producer and volatile primitive opaque; no whole-verifier, arbitrary cleanup panic, spill or native-platform proof; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
