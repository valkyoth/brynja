#!/usr/bin/env python3
"""Retained SHA-3 output adapter with the actual core completion/destructor path."""
import argparse
import json
from pathlib import Path
import re

import check_debug_output_begin as begin
import check_debug_output_finish as finish

comparison, model, require, bulk = begin.comparison, begin.model, begin.require, begin.bulk


def closure(case):
    _, names, _ = begin.guard.closure(case)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core')}
    roots = [name for name in bulk.calls(artifacts['sha3'][names['operation']]) if '13finish_secret' in name]
    require(len(roots) == 1, 'actual operation output completion adapter')
    root = roots[0]
    body = artifacts['sha3'][root]
    require(model.parameters(body) == ['%_0', '%initialization']
            and 'ptr sret([24 x i8]) align 8 %_0' in body.splitlines()[0], 'borrowed finish adapter ABI')
    selected, owners, aborts = {}, {}, set()
    pending = [(root, 'sha3')]
    while pending:
        name, source = pending.pop()
        if name in (names['wipe'], 'llvm.memcpy.p0.p0.i64'):
            continue
        if '16panic_in_cleanup' in name:
            aborts.add(name)
            continue
        if name not in artifacts[source]:
            matches = [key for key in artifacts if name in artifacts[key]]
            require(len(matches) == 1, 'unique actual finish adapter helper')
            source = matches[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed adapter ownership ABI')
        if name in selected:
            require(owners[name] == source or (model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name])), 'same shared finish helper')
            continue
        selected[name], owners[name] = body, source
        pending.extend((callee, source) for callee in bulk.calls(body))
    core_root, core_names, core_selected = finish.closure(case.core)
    require(len(selected) == 16 and len(aborts) == 1 and all(
        name in selected and selected[name] == body for name, body in core_selected.items() if name != names['wipe']),
        'sixteen actual adapter/core helpers, including core completion cleanup')
    return root, dict(names, core_finish=core_root, **core_names), selected


class AdapterModel(begin.guard.GuardModel):
    def __init__(self, functions, constants, names, length, fault):
        super().__init__(functions, constants, names, length, 0, 0, model.UNKNOWN, None, None, None)
        self.finish_fault = fault

    def run(self, name, args, depth=0):
        if name == self.names['core_finish']:
            result, owner = args
            progress = model.Pointer(owner.region, owner.offset + 16)
            original, initialized = self.load(owner, 8), self.load(progress, 8)
            try:
                outcome = super().run(name, args, depth)
            except model.Unwind:
                require(self.load(progress, 8) == initialized, 'unwind preserves initialization progress')
                raise
            require(self.load(progress, 8) == initialized, 'finish does not rewrite initialization progress')
            require(self.load(owner, 8) == (0 if self.load(result, 1) == 0 else original),
                    'core ownership revoked only by successful transfer')
            return outcome
        if self.finish_fault in ('deref-unwind', 'take-unwind'):
            role = self.finish_fault.split('-')[0]
            if name == self.names[role]:
                self.events.append(('unwind', role))
                raise model.Unwind(self.exception)
        if self.finish_fault == 'take-none' and name == self.names['take']:
            self.events.append(('none',))
            return (0, model.UNKNOWN)
        return super().run(name, args, depth)


def inspect(case):
    root, names, selected = closure(case)
    functions, constants = begin.functions_and_constants(case, selected)
    scenarios = [(False, False, 0, 0, None)] + [(True, *scenario) for scenario in finish.scenarios()]
    count, visited = 0, set()
    for outer, present, length, initialized, fault in scenarios:
        machine = AdapterModel(functions, constants, names, length, fault)
        result = machine.allocate('result', 24)
        descriptor = machine.allocate('initializer', 32)
        output = machine.allocate('output', length, payload=True)
        machine.fields(descriptor, [(0, 8, int(outer)), (8, 8, output if present else 0),
                                    (16, 8, length), (24, 8, initialized)])
        machine.events.clear()
        unwinds = fault in ('deref-unwind', 'take-unwind')
        try:
            require(machine.run(root, [result, descriptor]) is None, 'void adapter completion')
        except model.Unwind as error:
            require(unwinds and error.value == machine.exception, 'original completion exception')
        else:
            require(not unwinds, 'completion exception not swallowed')
        complete = present and initialized == length and fault is None
        expected = [('unwind', fault.split('-')[0])] if unwinds else [('none',)] if fault == 'take-none' else []
        if outer and present and not complete:
            expected.append(('wipe', 'output', 0, length))
        if not unwinds:
            if not outer:
                expected.append(('result', 0, 8, 0))
            elif complete:
                expected += [('result', 8, 8, output), ('result', 16, 8, length), ('result', 0, 8, 1)]
            else:
                expected += [('result', 8, 1, 4), ('result', 0, 8, 2)]
        require(machine.events == expected, 'exact empty/owned output or cleared error, with no payload reads/copies')
        visited.update(machine.visited)
        count += 1
    expected = {(name, label) for name, body in selected.items() for label, lines in model.blocks(body).items()
                if lines != ['unreachable'] and not any('16panic_in_cleanup' in line for line in lines)}
    require(visited == expected, 'all adapter/core blocks except unreachable and cleanup double panic covered')
    return count, selected, visited


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in begin.guard.final.cases(record)]
    require(len(results) == 16 and all(count == 71 for count, _, _ in results)
            and before == comparison.capture.sources(), 'complete unchanged debug adapter matrix')
    print('Debug finish adapter: 16 sixteen-function closures; 1,136 completion/error/unwind cases PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Volatile primitive opaque; helper faults synthetic; no squeeze/whole-verifier/spill/native proof; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
