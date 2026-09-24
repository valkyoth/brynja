#!/usr/bin/env python3
"""Compose retained portable producer guards, operation dispatch and completion."""
import argparse
import json
from pathlib import Path
import re

import check_debug_finish_adapter as finish

begin = finish.begin
comparison, model, require, bulk = begin.comparison, begin.model, begin.require, begin.bulk


def closure(case):
    versions = re.findall(r'^!\d+ = !\{!"rustc version (\S+) [^\n]+"\}$', case.sha3, re.M)
    require(len(versions) == 1 and versions[0] in ('1.90.0', '1.98.1'), 'known retained compiler result representation')
    producer, names, _, guarded = begin.closure(case)
    completion, completion_names, completed = finish.closure(case)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core')}
    operation = names['operation']
    boundaries = {}
    for role, token, types in (('empty_check', '18check_output_bytes', ('ptr', 'i128')),
                               ('squeeze', '14squeeze_secret', ('ptr', 'ptr', 'i64')),
                               ('final_squeeze', '25squeeze_final_bits_secret', ('ptr', 'i64', 'i8', 'ptr'))):
        matches = [name for name in bulk.calls(artifacts['sha3'][operation]) if token in name]
        require(len(matches) == 1, 'actual unique operation boundary: ' + role)
        name = boundaries[role] = matches[0]
        require(name in artifacts['sha3'], 'defined operation boundary')
        header = artifacts['sha3'][name].splitlines()[0]
        args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
        require(len(args) == len(types) and not re.search(r'\b(?:byval|inalloca)\b', header)
                and all(argument.startswith(kind + ' ') for argument, kind in zip(args, types))
                and header.startswith('define internal ' + ('zeroext i1' if role == 'empty_check' else 'i8') + ' @'),
                'borrowed squeeze/check boundary ABI')
    selected, owners, aborts = {}, {}, set()
    pending = [(operation, 'sha3')]
    while pending:
        name, source = pending.pop()
        if name in (*boundaries.values(), names['wipe'], 'llvm.memcpy.p0.p0.i64'):
            continue
        if '16panic_in_cleanup' in name:
            aborts.add(name)
            continue
        if name not in artifacts[source]:
            matches = [key for key in artifacts if name in artifacts[key]]
            require(len(matches) == 1, 'unique actual operation helper')
            source = matches[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed operation helper ABI')
        if name in selected:
            require(owners[name] == source or (model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name])), 'same instantiated operation helper')
            continue
        selected[name], owners[name] = body, source
        pending.extend((callee, source) for callee in bulk.calls(body))
    require(len(selected) == 24 and len(aborts) == 1 and all(name in selected and
            model.blocks(selected[name]) == model.blocks(body) for name, body in completed.items()),
            'complete operation and actual completion closure')
    merged = dict(guarded)
    for name, body in selected.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'same guard/operation helper')
        merged[name] = body
    require(len(merged) == len(guarded) + 16, 'full initializer/guard/operation/completion composition')
    return producer, dict(completion_names, **names, **boundaries, finish=completion,
                          success=5 if versions[0] == '1.90.0' else 255), selected, merged


class OperationModel(begin.BeginModel):
    def __init__(self, functions, constants, names, length, active, mode, valid, error, fault, clear_error, partial):
        super().__init__(functions, constants, names, length, active, mode, valid, error,
                         'predicate' if fault == 'predicate' else None, clear_error, True)
        self.operation_fault, self.partial = fault, partial

    def run(self, name, args, depth=0):
        if name == self.names['operation']:
            require(len(args) == 3 and args[2] == model.Pointer('storage')
                    and self.load(model.Pointer('reader', 8), 1) == 0, 'operation begins with original owner and armed guard')
            capture = args[1]
            require(isinstance(capture, model.Pointer), 'borrowed operation captures')
            at = lambda offset, width: self.load(model.Pointer(capture.region, capture.offset + offset), width)
            require(at(0, 8) == int(self.length != 0), 'original initializer presence')
            if self.length:
                require((at(8, 8), at(16, 8), at(24, 8)) == (model.Pointer('output'), self.length, 0),
                        'original zero-progress initializer')
            valid, length = at(32, 8), at(40, 8)
            require(self.load(length, 8) == self.length and self.load(valid, 1) == self.mode
                    and self.load(model.Pointer(valid.region, valid.offset + 1), 1) == self.valid,
                    'exact captured length and optional bit shape')
            self.events.append(('operation',))
            return model.Model.run(self, name, args, depth)
        if name == self.names['empty_check']:
            require(args == [model.Pointer('storage'), 0] and self.length == 0, 'empty admission on original owner and zero increment')
            self.events.append(('empty-check',))
            if self.operation_fault == 'squeeze':
                raise model.Unwind(self.exception)
            return int(self.error is not None)
        if name in (self.names['squeeze'], self.names['final_squeeze']):
            require(len(args) == (3 if name == self.names['squeeze'] else 4)
                    and self.length > 0 and args[0] == model.Pointer('storage'), 'original nonempty owner and squeeze ABI')
            if name == self.names['squeeze']:
                require(self.mode == 0 and args[2] == self.length, 'bulk dispatch and original length')
                initializer = args[1]
            else:
                require(self.mode == 1 and args[1:3] == [self.length, self.valid], 'final dispatch and original bit shape')
                initializer = args[3]
            require(isinstance(initializer, model.Pointer), 'borrowed squeeze initializer')
            at = lambda offset: self.load(model.Pointer(initializer.region, initializer.offset + offset), 8)
            require((at(0), at(8), at(16)) == (model.Pointer('output'), self.length, 0), 'original initializer borrowed by squeeze')
            self.events.append(('squeeze', self.mode))
            # Synthetic boundary effects: these are metadata handoff cases, not
            # execution/proof of a squeeze body or generation of secret bytes.
            progress = self.length // 2 if self.partial or self.error is not None else self.length
            self.store(model.Pointer(initializer.region, initializer.offset + 16), 8, progress)
            if self.operation_fault == 'squeeze':
                raise model.Unwind(self.exception)
            return self.names['success'] if self.error is None else self.error
        if name == self.names['finish']:
            self.events.append(('finish',))
        if self.operation_fault in ('deref-unwind', 'take-unwind'):
            role = self.operation_fault.split('-')[0]
            if name == self.names[role]:
                self.events.append(('unwind', role))
                raise model.Unwind(self.exception)
        if self.operation_fault == 'take-none' and name == self.names['take']:
            self.events.append(('none',))
            return (0, model.UNKNOWN)
        return super().run(name, args, depth)


def scenarios(thorough):
    lengths = (0, 1, 7, 135, 136, 167, 168, 169, 4096, (1 << 63) - 1) if thorough else (0, 169)
    for length in lengths:
        shapes = ((0, model.UNKNOWN), (0, 255), (1, 0), (1, 1), (1, 7), (1, 8), (1, 255)) if thorough else ((0, model.UNKNOWN), (1, 7))
        for mode, valid in shapes:
            for active in (0, 1):
                yield length, active, mode, valid, None, None, None, False
                if length:
                    for clear_error in range(4):
                        yield length, active, mode, valid, None, None, clear_error, False
            for error in range(5) if length else (2,):
                yield length, 1, mode, valid, error, None, None, False
            for fault in ('squeeze', 'predicate') + (('deref-unwind', 'take-unwind', 'take-none') if length else ()):
                yield length, 1, mode, valid, None, fault, None, False
            if length:
                yield length, 1, mode, valid, None, None, None, True


def inspect(case, thorough=True):
    producer, names, selected, merged = closure(case)
    functions, constants = begin.functions_and_constants(case, merged)
    cleanup = [('wipe', 'storage', offset, length) for offset, length in begin.guard.final.regions()]
    count, visited = 0, set()
    for length, active, mode, valid, error, fault, clear_error, partial in scenarios(thorough):
        machine = OperationModel(functions, constants, names, length, active, mode, valid, error, fault, clear_error, partial)
        result = machine.allocate('result', 24)
        reader = machine.allocate('reader', 16)
        storage = machine.allocate('storage', 1040, payload=True)
        output = machine.allocate('output', length, payload=True)
        machine.fields(reader, [(0, 8, storage), (8, 1, active)])
        machine.events.clear()
        unwinds = fault in ('squeeze', 'predicate', 'deref-unwind', 'take-unwind')
        try:
            require(machine.run(producer, [result, reader, output, length, mode, valid]) is None, 'void composed producer')
        except model.Unwind as failure:
            require(unwinds and failure.value == machine.exception, 'original composed operation exception')
        else:
            require(not unwinds, 'operation exception not swallowed')
        output_clear = [('wipe', 'output', 0, length)] if length else []
        expected = [('begin',)]
        final_error = 4 if clear_error is not None or partial or fault == 'take-none' else error
        success = active and final_error is None and fault is None
        if clear_error is not None:
            expected += [('clear-error', clear_error), ('reader', 8, 1, 0)] + cleanup + [('result', 8, 1, 4), ('result', 0, 8, 2)]
        else:
            expected += output_clear
            if not active:
                expected += [('result', 8, 1, 0), ('result', 0, 8, 2)] + output_clear
            else:
                expected += [('reader', 8, 1, 0), ('operation',), ('squeeze', mode) if length else ('empty-check',)]
                if error is None and fault != 'squeeze':
                    expected += [('finish',)]
                    if fault in ('deref-unwind', 'take-unwind'):
                        expected += [('unwind', fault.split('-')[0])]
                    elif fault == 'take-none':
                        expected += [('none',)]
                if fault == 'predicate':
                    expected += [('predicate-unwind',)] + output_clear + cleanup
                elif unwinds:
                    expected += output_clear + cleanup
                elif final_error is not None:
                    expected += output_clear + [('result', 8, 1, final_error), ('result', 0, 8, 2)] + cleanup
                else:
                    fields = ((8, 8, output), (16, 8, length), (0, 8, 1)) if length else ((0, 8, 0),)
                    expected += [('reader', 8, 1, 1)] + [('result', *field) for field in fields]
        require(machine.events == expected, 'exact dispatch/completion, output cleanup and guard lifecycle')
        require(machine.load(reader, 8) == storage and machine.load(model.Pointer('reader', 8), 1) == int(success),
                'original owner and success-only active state')
        visited.update(machine.visited)
        count += 1
    # Helpers' full standalone coverage is retained separately. Here qualify
    # every operation block, excluding only unreachable and double-panic abort.
    blocks = model.blocks(selected[names['operation']])
    expected = {label for label, lines in blocks.items() if lines != ['unreachable']
                and not any('16panic_in_cleanup' in line for line in lines)}
    require({label for name, label in visited if name == names['operation']} == expected, 'all operation blocks covered')
    return count, selected, merged, visited


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in begin.guard.final.cases(record)]
    require(len(results) == 16 and all(count == 1358 for count, _, _, _ in results)
            and before == comparison.capture.sources(), 'complete unchanged debug operation matrix')
    print('Debug producer operations: ' + repr([(count, len(merged)) for count, _, merged, _ in results]) + ' PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Squeeze/check/volatile bodies opaque; synthetic progress/errors/unwind; no whole-verifier/spill/native proof; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
