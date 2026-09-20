#!/usr/bin/env python3
"""Retained debug clearing loop/helpers under valid byte-pointer assumptions."""
import argparse
import json
from pathlib import Path
import re

import check_debug_output_write as writing
import debug_write_model as model

comparison = writing.comparison
require = comparison.require


def closure(core):
    definitions = comparison.definitions(core)
    roots = [name for name in definitions if 'secret_memory_volatile23zeroize_region_volatile' in name]
    require(len(roots) == 1, 'unique debug clearing entry')
    root = roots[0]
    header = definitions[root].splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    args = comparison.arguments(header, symbol.end())
    require(header.startswith('define internal void ') and len(args) == 2
            and comparison.pointer(args[0]) == '%region.0' and args[1] == 'i64 %region.1',
            'borrowed debug clearing ABI')
    selected, pending, excluded = {}, [root], set()
    while pending:
        name = pending.pop()
        if name in selected or name in excluded:
            continue
        if '9panic_fmt' in name:
            excluded.add(name)
            continue
        require(name in definitions, 'bound debug clearing helper: ' + name)
        selected[name] = definitions[name]
        if '14write_volatile18precondition_check' in name:
            continue
        for lines in model.blocks(definitions[name]).values():
            for line in lines:
                if re.search(r'\b(?:call|invoke) ', line):
                    symbol = re.search(comparison.SYMBOL, line)
                    require(symbol is not None, 'direct debug clearing call')
                    pending.append(symbol[1])
    require(len(selected) == 6 and len(excluded) == 1, 'six-function clearing closure plus excluded panic')
    checks = [name for name in selected if '14write_volatile18precondition_check' in name]
    require(len(checks) == 1, 'unique pointer-precondition boundary')
    return root, checks[0], selected


class ClearModel(model.Model):
    def __init__(self, functions, constants, precondition, length):
        super().__init__(functions, constants, '')
        self.precondition, self.length = precondition, length
        self.base = 17
        self.step_limit = 200 * (length + 1) + 1000
        self.local_cells = {}

    def store(self, ptr, width, value):
        # Per-allocation indexing avoids scanning every earlier debug frame for
        # each spill. Preserve the base model's overlapping-store semantics.
        self.address(ptr, width)
        require(not ptr.region.startswith('@'), 'read-only debug constant')
        cells = self.local_cells.setdefault(ptr.region, set())
        for other in tuple(cells):
            size, _ = self.memory[other]
            if max(other.offset, ptr.offset) < min(other.offset + size, ptr.offset + width):
                del self.memory[other]
                cells.remove(other)
        cells.add(ptr)
        self.memory[ptr] = (width, value)

    def byte_address(self, ptr):
        self.address(ptr, 1, access=False)
        require(ptr.region == 'payload' and self.base <= ptr.offset < self.base + self.length,
                'original live byte inside clearing slice')

    def run(self, name, args, depth=0):
        if name == self.precondition:
            require(len(args) == 3 and args[1] == 1, 'byte-alignment precondition arguments')
            self.byte_address(args[0])
            self.events.append(('check', args[0].offset))
            # Valid in-bounds, non-null u8 pointers satisfy the contract. This
            # models successful precondition return, not its panic implementation.
            return None
        return super().run(name, args, depth)

    def volatile_store(self, ptr, value):
        self.byte_address(ptr)
        require(type(value) is int and value == 0, 'volatile zero byte')
        self.events.append(('zero', ptr.offset))

    def compiler_fence(self, order):
        self.events.append(('fence', order))


def lengths():
    return tuple(range(34)) + (63, 64, 65, 127, 128, 129, 135, 136, 137,
                               167, 168, 169, 255, 256, 257, 511, 512, 513)


def inspect(core):
    root, precondition, selected = closure(core)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in selected.items()}
    constants = '\n'.join(line for line in core.splitlines() if line.startswith('@anon.'))
    visited = set()
    for length in lengths():
        machine = ClearModel(functions, constants, precondition, length)
        allocation = machine.allocate('payload', machine.base + length + 9, payload=True)
        start = model.Pointer(allocation.region, machine.base)
        require(machine.run(root, [start, length]) is None, 'void clearing result')
        expected = [event for offset in range(machine.base, machine.base + length)
                    for event in (('check', offset), ('zero', offset))] + [('fence', 'seq_cst')]
        require(machine.events == expected, 'checked volatile zero of each original byte followed by SeqCst fence')
        visited.update(machine.visited)
    for name, (_, graph) in functions.items():
        if name == precondition or '14compiler_fence' in name:
            continue
        reachable = {label for label, lines in graph.items() if lines != ['unreachable']}
        require({label for callee, label in visited if callee == name} == reachable,
                'all live clearing/iterator/write blocks visited')
    return len(lengths())


def main(record):
    before = comparison.capture.sources()
    builds = count = 0
    for core, _, _, _ in writing.cases(record):
        count += inspect(core)
        builds += 1
    require(builds == 8 and before == comparison.capture.sources(), 'complete unchanged debug matrix')
    print(f'Debug volatile clear: {builds} six-function closures, {count} modeled lengths PASS')
    print('Actual iterator and volatile-write bodies evaluated; valid byte-pointer precondition return assumed')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not all-length proof, pointer-precondition panic proof, final assembly, whole-call spills or native-platform evidence; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
