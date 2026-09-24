#!/usr/bin/env python3
"""Retained portable producer initialization handoff and operation-guard cleanup."""
import argparse
import json
from pathlib import Path
import re

import check_debug_portable_final_bridge as final

comparison, model, require, bulk = final.comparison, final.model, final.require, final.bulk


def closure(case):
    root, _, _, _ = final.closure(case)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core')}
    sha3 = artifacts['sha3']
    begin = [name for name in bulk.calls(sha3[root]) if '12begin_secret' in name]
    guards = [name for name in bulk.calls(sha3[root]) if 'Borrowed' in name and '3run' in name]
    require(len(begin) == len(guards) == 1, 'one actual initializer and operation guard')
    begin, guard = begin[0], guards[0]
    require(begin in sha3 and guard in sha3, 'defined initializer and guard')
    operations = [name for name in bulk.calls(sha3[guard]) if '6secret28_' in name
                  or (name.startswith('_RNCNv') and 'Borrowed' in name and '6secret0' in name)]
    require(len(operations) == 1 and operations[0] in sha3, 'one actual consuming operation closure')
    operation = operations[0]
    for name, size, params in ((begin, 32, ['%_0', '%destination.0', '%destination.1']),
                               (guard, 24, ['%_0', '%self', '%operation']),
                               (operation, 24, ['%_0', '%_1', '%owner'])):
        body = sha3[name]
        header = body.splitlines()[0]
        args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
        require(header.startswith('define ') and len(args) == 3
                and args[0] == f'ptr sret([{size} x i8]) align 8 %_0'
                and model.parameters(body) == params and not re.search(r'\b(?:byval|inalloca)\b', header),
                'bound borrowed initialization/guard/operation ABI')
        comparison.pointer(args[1])
        require(args[2] == 'i64 %destination.1' if name == begin else comparison.pointer(args[2]) == params[2],
                'original length or borrowed operation storage')
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
            matches = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(matches) == 1, 'unambiguous defined guard helper: ' + name)
            source = matches[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed guard/cleanup helper')
        if 'secret_memory_volatile23zeroize_region_volatile' in name:
            header = body.splitlines()[0]
            args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
            require(header.startswith('define internal void @') and len(args) == 2
                    and comparison.pointer(args[0]) == '%region.0' and args[1] == 'i64 %region.1', 'actual volatile boundary ABI')
            wipes.add(name)
            continue
        if name in selected:
            require(owners[name] == source or (model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name])), 'identical instantiated helper')
            continue
        selected[name], owners[name] = body, source
        pending.extend((callee, source) for callee in bulk.calls(body))
    predicates = [name for name in selected if '5is_ok' in name]
    require(len(selected) == 19 and len(wipes) == len(aborts) == len(predicates) == 1,
            'nineteen-function closure plus clear, abort and result predicate')
    return root, dict(begin=begin, operation=operation, wipe=wipes.pop(), predicate=predicates[0]), selected


class GuardModel(model.Model):
    def __init__(self, functions, constants, names, length, active, mode, valid, begin_error, error, fault):
        super().__init__(functions, constants, '')
        self.names, self.length, self.active = names, length, active
        self.mode, self.valid, self.begin_error, self.error, self.boundary_fault = mode, valid, begin_error, error, fault
        self.exception = (model.Pointer('exception', 7), 19)

    def store(self, ptr, width, value):
        super().store(ptr, width, value)
        if ptr.region in ('reader', 'result'):
            self.events.append((ptr.region, ptr.offset, width, value))

    def fields(self, pointer, fields):
        for offset, width, value in fields:
            self.store(model.Pointer(pointer.region, pointer.offset + offset), width, value)

    def run(self, name, args, depth=0):
        if name == self.names['begin']:
            require(len(args) == 3 and args[1:] == [model.Pointer('output'), self.length], 'original destination initialization')
            require(self.load(model.Pointer('reader', 8), 1) == self.active, 'initializer precedes reader-state mutation')
            self.events.append(('begin',))
            if self.begin_error is not None:
                self.fields(args[0], [(0, 8, 2), (8, 1, self.begin_error)])
            else:
                self.fields(args[0], [(0, 8, int(self.length != 0))])
                if self.length:
                    self.fields(args[0], [(8, 8, model.Pointer('output')), (16, 8, self.length), (24, 8, 0)])
            return None
        if name == self.names['operation']:
            require(len(args) == 3 and args[2] == model.Pointer('storage')
                    and self.load(model.Pointer('reader', 8), 1) == 0, 'original owner with guard armed before operation')
            closure = args[1]
            at = lambda offset, width: self.load(model.Pointer(closure.region, closure.offset + offset), width)
            require(at(0, 8) == int(self.length != 0), 'original initializer presence')
            if self.length:
                require((at(8, 8), at(16, 8), at(24, 8)) == (model.Pointer('output'), self.length, 0),
                        'whole original initializer transferred to operation')
            valid, length = at(32, 8), at(40, 8)
            require(self.load(length, 8) == self.length and self.load(valid, 1) == self.mode
                    and self.load(model.Pointer(valid.region, valid.offset + 1), 1) == self.valid,
                    'original length and optional bit-tail capture')
            self.events.append(('operation',))
            if self.boundary_fault == 'operation':
                raise model.Unwind(self.exception)
            fields = [(0, 8, 2), (8, 1, self.error)] if self.error is not None else [
                (0, 8, int(self.length != 0)), (8, 8, model.Pointer('output')), (16, 8, self.length)]
            self.fields(args[0], fields)
            return None
        if name == self.names['predicate'] and self.boundary_fault == 'predicate':
            self.events.append(('predicate-unwind',))
            raise model.Unwind(self.exception)
        if name == self.names['wipe']:
            require(len(args) == 2 and isinstance(args[0], model.Pointer) and type(args[1]) is int
                    and args[0].region in ('storage', 'output'), 'original owned clear region')
            self.address(args[0], args[1], access=False)
            self.events.append(('wipe', args[0].region, args[0].offset, args[1]))
            return None
        if name == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[2] in (24, 32, 48) and args[3] == 0, 'whole nonvolatile ownership descriptor move')
            destination, source, length, _ = args
            self.address(source, length)
            self.address(destination, length)
            require(source.region != destination.region, 'nonoverlapping descriptor storage')
            fields = [(ptr.offset - source.offset, width, value) for ptr, (width, value) in self.memory.items()
                      if ptr.region == source.region and source.offset <= ptr.offset < source.offset + length]
            require(all(offset + width <= length for offset, width, _ in fields), 'whole typed ownership fields')
            self.fields(destination, fields)
            return None
        return super().run(name, args, depth)


def scenarios(thorough):
    lengths = (0, 1, 135, 136, 167, 168, 169, 4096, (1 << 63) - 1) if thorough else (0, 169)
    for length in lengths:
        for mode, valid in ((0, 0), (0, 255), (0, model.UNKNOWN), (1, 0), (1, 1), (1, 7), (1, 8), (1, 255)) if thorough else ((0, model.UNKNOWN), (1, 7)):
            for active in (0, 1):
                for begin_error in range(5):
                    yield length, active, mode, valid, begin_error, None, None
                yield length, active, mode, valid, None, None, None
                if active:
                    yield length, active, mode, valid, None, None, 'operation'
                    for error in (None, 0, 1, 2, 3, 4):
                        if error is not None:
                            yield length, active, mode, valid, None, error, None
                        yield length, active, mode, valid, None, error, 'predicate'


def inspect(case, thorough=True):
    root, names, selected = closure(case)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in selected.items()}
    constants = '\n'.join(dict.fromkeys(line for text in (case.sha3, case.core)
                                      for line in text.splitlines() if line.startswith(('@anon.', '@alloc_'))))
    cleanup = [('wipe', 'storage', offset, length) for offset, length in final.regions()]
    visited, count = set(), 0
    for length, active, mode, valid, begin_error, error, fault in scenarios(thorough):
        machine = GuardModel(functions, constants, names, length, active, mode, valid, begin_error, error, fault)
        result = machine.allocate('result', 24)
        reader = machine.allocate('reader', 16)
        storage = machine.allocate('storage', 1040, payload=True)
        output = machine.allocate('output', length, payload=True)
        machine.fields(reader, [(0, 8, storage), (8, 1, active)])
        machine.events.clear()
        try:
            require(machine.run(root, [result, reader, output, length, mode, valid]) is None, 'void producer handoff')
        except model.Unwind as failure:
            require(fault is not None and failure.value == machine.exception, 'original boundary exception resumed')
        else:
            require(fault is None, 'boundary unwind cannot be swallowed')
        result_fields = lambda failure: [('result', 8, 1, failure), ('result', 0, 8, 2)]
        output_clear = [('wipe', 'output', 0, length)] if length else []
        expected = [('begin',)]
        if begin_error is not None:
            expected += [('reader', 8, 1, 0)] + cleanup + result_fields(begin_error)
        elif not active:
            expected += result_fields(0) + output_clear
        else:
            expected += [('reader', 8, 1, 0), ('operation',)]
            if fault == 'predicate':
                expected += [('predicate-unwind',)] + (output_clear if error is None else []) + cleanup
            elif fault == 'operation':
                expected += cleanup
            else:
                if error is None:
                    expected += [('reader', 8, 1, 1)] + [('result', *field) for field in
                        ((0, 8, int(length != 0)), (8, 8, output), (16, 8, length))]
                else:
                    expected += [('result', 0, 8, 2), ('result', 8, 1, error)] + cleanup
        require(machine.events == expected, 'exact initialization/ownership/result/cleanup ordering')
        require(machine.load(reader, 8) == storage and machine.load(model.Pointer('reader', 8), 1) ==
                int(active and begin_error is None and error is None and fault is None), 'only success restores active state')
        visited.update(machine.visited)
        count += 1
    expected = set()
    for name, (_, graph) in functions.items():
        for label, lines in graph.items():
            if lines == ['unreachable'] or any('16panic_in_cleanup' in line for line in lines):
                continue
            # The initializer has moved before the root's only invoke; this
            # compiler-created pre-transfer unwind arm has no throwing edge.
            if name == root and label == 'bb9':
                require(any('SecretRegionInitialization' in line for line in lines), 'known moved-initializer unwind arm')
                continue
            # Valid present initializer/output owners contain an actual slice;
            # empty output is represented by the outer None, not an inner None.
            if '12as_deref_mut' in name and any(line.startswith('store ptr null,') for line in lines):
                continue
            if 'secret_memory18clear_owned_region' in name and any(line.startswith('store i8 0,') for line in lines):
                continue
            expected.add((name, label))
    require(visited == expected, 'all selected initialization/guard/destructor/error/unwind blocks covered')
    return count, visited, selected


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in final.cases(record)]
    require(len(results) == 16 and all(count == 1728 for count, _, _ in results)
            and before == comparison.capture.sources(), 'unchanged complete portable debug matrix')
    print('Portable producer guards: ' + repr([(count, len(selected)) for count, _, selected in results]) + ' PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Initializer/operation/volatile bodies opaque; synthetic boundary unwind only; no register/spill/native proof; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
