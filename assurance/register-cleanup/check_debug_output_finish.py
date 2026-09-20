#!/usr/bin/env python3
"""Retained debug output ownership/cleanup requests, not volatile erasure proof."""
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
    roots = [name for name in definitions if 'SecretRegionInitialization6finish' in name]
    require(len(roots) == 1, 'unique debug finish entry')
    root = roots[0]
    header = definitions[root].splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    args = comparison.arguments(header, symbol.end())
    require(header.startswith('define void ') and len(args) == 2
            and args[0] == 'ptr sret([24 x i8]) align 8 %_0'
            and comparison.pointer(args[1]) == '%self', 'finish descriptor ABI')
    selected, pending, external = {}, [root], set()
    while pending:
        name = pending.pop()
        if name in selected or name in external:
            continue
        if '16panic_in_cleanup' in name:
            external.add(name)
            continue
        require(name in definitions, 'bound finish helper: ' + name)
        selected[name] = definitions[name]
        if 'secret_memory_volatile23zeroize_region_volatile' in name:
            continue
        for lines in model.blocks(definitions[name]).values():
            for line in lines:
                if re.search(r'\b(?:call|invoke) ', line):
                    symbol = re.search(comparison.SYMBOL, line)
                    require(symbol is not None, 'direct finish helper call')
                    pending.append(symbol[1])
    require(len(selected) == 9 and len(external) == 1, 'nine-function closure plus excluded cleanup abort')
    names = {}
    for role, token in (('wipe', 'secret_memory_volatile23zeroize_region_volatile'),
                        ('deref', '8as_deref'), ('take', '4take')):
        matches = [name for name in selected if token in name]
        require(len(matches) == 1, 'unique finish boundary ' + role)
        names[role] = matches[0]
    return root, names, selected


class FinishModel(model.Model):
    def __init__(self, functions, constants, names, fault):
        super().__init__(functions, constants, '')
        self.names, self.finish_fault = names, fault
        self.exception_identity = (model.Pointer('exception-token', 7), 19)

    def store(self, ptr, width, value):
        super().store(ptr, width, value)
        if ptr.region == 'result':
            self.events.append(('result', ptr.offset, width, value))

    def run(self, name, args, depth=0):
        if name == self.names['wipe']:
            require(len(args) == 2 and type(args[1]) is int, 'borrowed wipe request ABI')
            self.address(args[0], args[1], access=False)
            self.events.append(('wipe', *args))
            return None
        if self.finish_fault in ('deref-unwind', 'take-unwind'):
            role = self.finish_fault.split('-')[0]
            if name == self.names[role]:
                self.events.append(('unwind', role))
                raise model.Unwind(self.exception_identity)
        if self.finish_fault == 'take-none' and name == self.names['take']:
            self.events.append(('none',))
            return (0, model.UNKNOWN)
        return super().run(name, args, depth)


def scenarios():
    for capacity in (0, 1, 8, 64, 168, 4096, (1 << 63) - 1):
        for present, initialized in ((False, 0), (True, capacity),
                                      (True, max(0, capacity - 1)), (True, capacity + 1)):
            yield present, capacity, initialized, None
            yield present, capacity, initialized, 'deref-unwind'
        yield True, capacity, capacity, 'take-unwind'
        yield True, capacity, capacity, 'take-none'


def inspect(core):
    root, names, selected = closure(core)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in selected.items()}
    constants = '\n'.join(line for line in core.splitlines() if line.startswith('@anon.'))
    count, covered = 0, set()
    for present, capacity, initialized, fault in scenarios():
        machine = FinishModel(functions, constants, names, fault)
        owner = machine.allocate('owner', 24)
        result = machine.allocate('result', 24)
        payload = machine.allocate('payload', capacity, payload=True)
        machine.store(owner, 8, payload if present else 0)
        machine.store(model.Pointer('owner', 8), 8, capacity)
        machine.store(model.Pointer('owner', 16), 8, initialized)
        machine.events.clear()
        complete = present and initialized == capacity and fault is None
        unwinds = fault in ('deref-unwind', 'take-unwind')
        try:
            require(machine.run(root, [result, owner]) is None, 'void ownership handoff result')
        except model.Unwind as error:
            require(unwinds and error.value == machine.exception_identity, 'resume original exception identity')
        else:
            require(not unwinds, 'injected exception must resume')
        side_effects = [event for event in machine.events if event[0] != 'result']
        expected = []
        if unwinds:
            expected.append(('unwind', fault.split('-')[0]))
        if fault == 'take-none':
            expected.append(('none',))
        if complete:
            expected.extend([('store', 0, 8, 0), ('store', 8, 8, model.UNKNOWN)])
        elif present:
            expected.append(('wipe', payload, capacity))
        require(side_effects == expected, 'exact ownership transfer or full original-region wipe request')
        written = [event[1:] for event in machine.events if event[0] == 'result']
        expected_result = [] if unwinds else [(8, 8, payload), (16, 8, capacity), (0, 1, 0)] if complete else [(1, 1, 3), (0, 1, 1)]
        require(written == expected_result, 'exact descriptor/error handoff, no result on unwind')
        require(machine.load(model.Pointer('owner', 16), 8) == initialized, 'finish does not alter progress metadata')
        require(machine.load(owner, 8) == (0 if complete or not present else payload), 'owner consumed only on successful transfer')
        covered.update(label for name, label in machine.visited if name == root)
        count += 1
    graph = functions[root][1]
    excluded = {label for label, lines in graph.items() if lines == ['unreachable']
                or any('16panic_in_cleanup' in line for line in lines)}
    require(len(excluded) == 2 and covered == set(graph) - excluded,
            'all finish entry blocks except unreachable/double-panic abort inspected')
    return count


def main(record):
    before = comparison.capture.sources()
    builds = count = 0
    for core, _, _, _ in writing.cases(record):
        count += inspect(core)
        builds += 1
    require(builds == 8 and before == comparison.capture.sources(), 'unchanged complete debug matrix')
    print(f'Debug output finish: {builds} nine-function closures, {count} normal/synthetic-failure/unwind cases PASS')
    print('Original descriptor transferred on completion; otherwise full original-region wipe requested; original exception resumed')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Wipe is opaque; not volatile-callee erasure, double-panic/abort behavior, complete LLVM semantics, spills or native-platform qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
