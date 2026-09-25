#!/usr/bin/env python3
"""Retained accelerated debug guard/cleanup; initializer and operation opaque."""
import argparse
import json
from pathlib import Path
import re

import check_debug_kmac_final_bridge as final
import check_debug_portable_producer_guard as portable

model, comparison, require, bulk = final.model, final.comparison, final.require, final.bulk


def closure(case):
    root, _, _ = final.closure(case)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core')}
    sha3 = artifacts['sha3']
    unique = lambda names: next(iter(names)) if len(names) == 1 else require(False, 'unique accelerated guard dependency')
    begin = unique([n for n in bulk.calls(sha3[root]) if '12begin_secret' in n])
    guard = unique([n for n in bulk.calls(sha3[root]) if 'Borrowed' in n and '3run' in n])
    operation = unique([n for n in bulk.calls(sha3[guard]) if '6secret28_' in n
                        or (n.startswith('_RNCNv') and 'Borrowed' in n and '6secret0' in n)])
    for name, size, params in ((begin, 32, ['%_0', '%destination.0', '%destination.1']),
                               (guard, 24, ['%_0', '%self', '%operation']),
                               (operation, 24, ['%_0', '%_1', '%storage'])):
        require(name in sha3, 'defined actual accelerated boundary')
        body = sha3[name]
        args = comparison.arguments(body.splitlines()[0], re.search(comparison.SYMBOL, body).end())
        require(len(args) == 3 and args[0] == f'ptr sret([{size} x i8]) align 8 %_0'
                and model.parameters(body) == params and not re.search(r'\b(?:byval|inalloca)\b', body.splitlines()[0]),
                'bound borrowed accelerated initializer/guard/operation ABI')
        comparison.pointer(args[1])
        require(args[2] == 'i64 %destination.1' if name == begin else comparison.pointer(args[2]) == params[2],
                'original length or borrowed accelerated operation storage')
    selected, owners, wipes, aborts = {}, {}, set(), set()
    pending = [(root, 'sha3')]
    while pending:
        name, source = pending.pop()
        if name in (begin, operation, 'llvm.memcpy.p0.p0.i64'):
            continue
        if '16panic_in_cleanup' in name:
            aborts.add(name)
            continue
        if name not in artifacts[source]:
            source = unique([key for key, definitions in artifacts.items() if name in definitions])
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed accelerated guard/cleanup ABI')
        if 'secret_memory_volatile23zeroize_region_volatile' in name:
            args = comparison.arguments(body.splitlines()[0], re.search(comparison.SYMBOL, body).end())
            require(body.startswith('define internal void @') and len(args) == 2
                    and comparison.pointer(args[0]) == '%region.0' and args[1] == 'i64 %region.1', 'borrowed volatile primitive ABI')
            wipes.add(name)
            continue
        if name in selected:
            require(owners[name] == source or (model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name])), 'identical shared guard helper')
            continue
        selected[name], owners[name] = body, source
        pending.extend((callee, source) for callee in bulk.calls(body))
    predicate = unique([n for n in selected if '5is_ok' in n])
    require(len(selected) == 22 and len(wipes) == len(aborts) == 1, '22 helpers plus volatile and double-panic boundaries')
    return root, dict(begin=begin, guard=guard, operation=operation, predicate=predicate, wipe=wipes.pop()), selected


class GuardModel(portable.GuardModel):
    def __init__(self, functions, constants, names, length, mode, valid, begin_error, error, fault):
        super().__init__(functions, constants, names, length, 0, mode, valid, begin_error, error, fault)
        self.in_guard, self.guard_pointer, self.guard_stores = False, None, []

    def store(self, ptr, width, value):
        if isinstance(ptr, model.Pointer) and ptr.region == 'storage':
            require((ptr.offset, width, value) in ((859, 1, 1), (616, 8, 0)), 'only terminal accelerated storage metadata stores')
            self.address(ptr, width, access=False)
            self.events.append(('state', ptr.offset, width, value))
            return
        super().store(ptr, width, value)
        if self.guard_pointer and ptr == model.Pointer(self.guard_pointer.region, 8):
            require(width == 1 and value in (0, 1), 'local guard completion bit')
            self.guard_stores.append(value)

    def run(self, name, args, depth=0):
        if name == self.names['begin']:
            require(len(args) == 3 and args[1:] == [model.Pointer('output'), self.length] and not self.in_guard,
                    'whole original destination initialized before operation guard')
            self.events.append(('begin',))
            fields = [(0, 8, 2), (8, 1, self.begin_error)] if self.begin_error is not None else [(0, 8, int(self.length != 0))]
            if self.begin_error is None and self.length:
                fields += [(8, 8, model.Pointer('output')), (16, 8, self.length), (24, 8, 0)]
            self.fields(args[0], fields)
            return None
        if name == self.names['guard']:
            require(len(args) == 3 and args[1] == model.Pointer('reader') and not self.in_guard, 'original nonrecursive guard entry')
            self.guard_pointer = model.Pointer(f'{self.frames + 1}:%guard')
            self.in_guard = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.in_guard = False
        if name == self.names['operation']:
            require(self.in_guard and len(args) == 3 and args[2] == model.Pointer('storage')
                    and self.load(self.guard_pointer, 8) == model.Pointer('storage')
                    and self.load(model.Pointer(self.guard_pointer.region, 8), 1) == 0,
                    'original storage under armed local accelerated guard')
            capture = args[1]
            at = lambda offset, width: self.load(model.Pointer(capture.region, capture.offset + offset), width)
            require(at(0, 8) == int(self.length != 0), 'original initializer presence')
            if self.length:
                require((at(8, 8), at(16, 8), at(24, 8)) == (model.Pointer('output'), self.length, 0), 'complete original zero-progress initializer')
            valid, length = at(32, 8), at(40, 8)
            require(self.load(length, 8) == self.length and self.load(valid, 1) == self.mode
                    and self.load(model.Pointer(valid.region, valid.offset + 1), 1) == self.valid, 'original length/mode/bit-tail capture')
            self.events.append(('operation',))
            if self.boundary_fault == 'operation':
                raise model.Unwind(self.exception)
            fields = [(0, 8, 2), (8, 1, self.error)] if self.error is not None else [
                (0, 8, int(self.length != 0)), (8, 8, model.Pointer('output')), (16, 8, self.length)]
            self.fields(args[0], fields)
            return None
        return super().run(name, args, depth)


def scenarios(thorough):
    for length in (0, 1, 135, 136, 168, 169, (1 << 63) - 1) if thorough else (0, 169):
        for mode, valid in ((0, model.UNKNOWN), (0, 255), (1, 0), (1, 7), (1, 8), (1, 255)) if thorough else ((0, model.UNKNOWN), (1, 7)):
            for begin_error in range(5):
                yield length, mode, valid, begin_error, None, None
            yield length, mode, valid, None, None, None
            yield length, mode, valid, None, None, 'operation'
            for error in (None, *range(12)):
                if error is not None:
                    yield length, mode, valid, None, error, None
                yield length, mode, valid, None, error, 'predicate'


def inspect(case, thorough=True):
    root, names, selected = closure(case)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in selected.items()}
    constants = '\n'.join(dict.fromkeys(line for text in (case.sha3, case.core)
                                      for line in text.splitlines() if line.startswith(('@anon.', '@alloc_'))))
    cleanup = [('state', 859, 1, 1), ('state', 616, 8, 0)] + [
        ('wipe', 'storage', offset, width) for offset, width in ((656, 200), (624, 16), (640, 16), (856, 2), (864, 168), (1056, 2))]
    count, visited = 0, set()
    for length, mode, valid, begin_error, error, fault in scenarios(thorough):
        machine = GuardModel(functions, constants, names, length, mode, valid, begin_error, error, fault)
        result = machine.allocate('result', 24)
        reader = machine.allocate('reader', 8)
        storage = machine.allocate('storage', 1088, payload=True)
        output = machine.allocate('output', length, payload=True)
        machine.fields(reader, [(0, 8, storage)])
        machine.events.clear()
        unwound = False
        try:
            require(machine.run(root, [result, reader, output, length, mode, valid]) is None, 'void accelerated producer')
        except model.Unwind as failure:
            require(failure.value == machine.exception, 'original boundary exception preserved')
            unwound = True
        expected = [('begin',)]
        if begin_error is not None:
            expected += cleanup + [('result', 8, 1, 10), ('result', 0, 8, 2)]
        else:
            expected += [('operation',)]
            if fault == 'operation':
                expected += cleanup
            elif fault == 'predicate':
                expected += [('predicate-unwind',)] + ([('wipe', 'output', 0, length)] if error is None and length else []) + cleanup
            elif error is None:
                expected += [('result', *field) for field in ((0, 8, int(length != 0)), (8, 8, output), (16, 8, length))]
                expected += [('wipe', 'storage', 864, 168)]
            else:
                expected += [('result', 0, 8, 2), ('result', 8, 1, error)] + cleanup
        require(machine.events == expected and unwound == (fault is not None), 'exact accelerated guard/error/cleanup/unwind trace: '
                + repr((length, mode, valid, begin_error, error, fault)) + '; actual=' + repr(machine.events))
        require(machine.load(reader, 8) == storage and not machine.in_guard and machine.guard_stores == (
            [] if begin_error is not None else [0, 1] if error is None and fault is None else [0]),
            'only successful operation disarms original local guard')
        visited.update(machine.visited)
        count += 1
    for name in (root, names['guard']):
        for label, lines in model.blocks(selected[name]).items():
            if lines == ['unreachable'] or any('16panic_in_cleanup' in line for line in lines):
                continue
            if name == root and label == 'bb10':
                require(any('SecretRegionInitialization' in line for line in lines), 'known pre-transfer initializer unwind arm')
                continue
            require((name, label) in visited, 'all selected root/local-guard blocks exercised')
    return count, visited, selected


def main(record, shard=None):
    before = comparison.capture.sources()
    cases = list(final.cases(record))
    require(len(cases) == 8 and (shard is None or shard in range(8)), 'eight accelerated debug paths and valid shard')
    results = []
    for case in cases if shard is None else [cases[shard]]:
        count, _, selected = inspect(case)
        results.append(count)
        print(f'Accelerated debug guard: {count} cases; {len(selected)} functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all 8 paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Guard cases: ' + str(sum(results)))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Initializer/operation/volatile bodies opaque; synthetic faults; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
