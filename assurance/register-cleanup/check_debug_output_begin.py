#!/usr/bin/env python3
"""Retained destination-initializer body and composition with portable guards."""
import argparse
import json
from pathlib import Path
import re

import check_debug_portable_producer_guard as guard

comparison, model, require, bulk = guard.comparison, guard.model, guard.require, guard.bulk


def closure(case):
    producer, names, guarded = guard.closure(case)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core', 'hash_core', 'kmac')}
    root = names['begin']
    pending, selected, owners, aborts = [(root, 'sha3')], {}, {}, set()
    while pending:
        name, source = pending.pop()
        if name in (names['wipe'], 'llvm.memcpy.p0.p0.i64'):
            continue
        if '16panic_in_cleanup' in name:
            aborts.add(name)
            continue
        if name not in artifacts[source]:
            matches = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(matches) == 1, 'actual unique initializer helper: ' + name)
            source = matches[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed destination initializer ABI')
        if name in selected:
            require(owners[name] == source or (model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name])), 'same instantiated initializer helper')
            continue
        selected[name], owners[name] = body, source
        pending.extend((callee, source) for callee in bulk.calls(body))
    clears = [name for name in selected if '18clear_owned_region' in name]
    core_begins = [name for name in selected if '26SecretRegionInitialization5begin' in name]
    empty_helpers = [name for name in selected if '8is_empty' in name]
    require(len(empty_helpers) in (1, 2) and len(selected) == 11 + len(empty_helpers)
            and not aborts and len(clears) == len(core_begins) == 1,
            'complete initializer closure with actual core begin/clear and slice helpers')
    header = selected[core_begins[0]].splitlines()[0]
    args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    require(header.startswith('define void @') and len(args) == 3
            and args[0] == 'ptr sret([32 x i8]) align 8 %_0'
            and comparison.pointer(args[1]) == '%region.0' and args[2] == 'i64 %region.1', 'actual core initializer ABI')
    merged = dict(guarded)
    for name, body in selected.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'same initializer/guard shared helper')
        merged[name] = body
    require(len(merged) == 28 + len(empty_helpers), 'complete initializer and guard composition')
    return producer, dict(names, clear=clears[0], core_begin=core_begins[0]), selected, merged


class BeginModel(guard.GuardModel):
    def __init__(self, functions, constants, names, length, active, mode, valid, error, fault, clear_error, composed):
        super().__init__(functions, constants, names, length, active, mode, valid, None, error, fault)
        self.clear_error, self.composed = clear_error, composed
        self.inside_begin = False

    def run(self, name, args, depth=0):
        if name == self.names['begin']:
            require(len(args) == 3 and args[1:] == [model.Pointer('output'), self.length], 'original initializer destination')
            if self.composed:
                require(self.load(model.Pointer('reader', 8), 1) == self.active, 'initializer before state mutation')
            self.events.append(('begin',))
            self.inside_begin = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.inside_begin = False
        if name == self.names['clear'] and self.inside_begin and self.clear_error is not None:
            require(args == [model.Pointer('output'), self.length] and self.length > 0, 'fault at original nonempty clearing request')
            self.events.append(('clear-error', self.clear_error))
            return self.clear_error
        return super().run(name, args, depth)


def functions_and_constants(case, selected):
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in selected.items()}
    constants = '\n'.join(dict.fromkeys(line for text in (case.sha3, case.core, case.hash_core, case.kmac)
                                      for line in text.splitlines() if line.startswith(('@anon.', '@alloc_'))))
    return functions, constants


def inspect(case, thorough=True):
    producer, names, selected, merged = closure(case)
    functions, constants = functions_and_constants(case, merged)
    visited, count = set(), 0
    lengths = (0, 1, 7, 135, 136, 167, 168, 169, 4096, (1 << 63) - 1) if thorough else (0, 169)
    cleanup = [('wipe', 'storage', offset, length) for offset, length in guard.final.regions()]
    for length in lengths:
        for clear_error in (None, 0, 1, 2, 3) if length else (None,):
            # Check the public core constructor independently, before the SHA-3
            # adapter deliberately collapses its error identity to SecretMemory.
            machine = BeginModel(functions, constants, names, length, 0, 0, model.UNKNOWN, None, None, clear_error, False)
            result = machine.allocate('result', 32)
            output = machine.allocate('output', length, payload=True)
            machine.inside_begin = True
            require(machine.run(names['core_begin'], [result, output, length]) is None, 'void core initializer')
            if length and clear_error is None:
                expected = [('wipe', 'output', 0, length)] + [('result', *field) for field in
                    ((8, 8, output), (16, 8, length), (24, 8, 0), (0, 1, 0))]
            else:
                expected = ([('clear-error', clear_error)] if length else []) + [
                    ('result', 1, 1, clear_error if length else 0), ('result', 0, 1, 1)]
            require(machine.events == expected, 'core empty-region rejection, exact error or complete zero-progress owner')
            visited.update(machine.visited)
            count += 1
            machine = BeginModel(functions, constants, names, length, 0, 0, model.UNKNOWN, None, None, clear_error, False)
            result = machine.allocate('result', 32)
            output = machine.allocate('output', length, payload=True)
            require(machine.run(names['begin'], [result, output, length]) is None, 'void initializer result')
            if not length:
                expected = [('begin',), ('result', 0, 8, 0)]
            elif clear_error is None:
                expected = [('begin',), ('wipe', 'output', 0, length)] + [('result', *field) for field in
                    ((8, 8, output), (16, 8, length), (24, 8, 0), (0, 8, 1))]
            else:
                expected = [('begin',), ('clear-error', clear_error), ('result', 8, 1, 4), ('result', 0, 8, 2)]
            require(machine.events == expected, 'empty None or cleared whole original destination and zero-progress initializer; exact error')
            visited.update(machine.visited)
            count += 1
            for active in (0, 1):
                for mode, valid in ((0, model.UNKNOWN), (1, 7)):
                    outcomes = [(None, None)]
                    if active and clear_error is None:
                        outcomes += [(None, 'operation')] + [(value, None) for value in range(5)]
                        outcomes += [(None, 'predicate'), (4, 'predicate')]
                    for error, fault in outcomes:
                        machine = BeginModel(functions, constants, names, length, active, mode, valid, error, fault, clear_error, True)
                        result = machine.allocate('result', 24)
                        reader = machine.allocate('reader', 16)
                        storage = machine.allocate('storage', 1040, payload=True)
                        output = machine.allocate('output', length, payload=True)
                        machine.fields(reader, [(0, 8, storage), (8, 1, active)])
                        machine.events.clear()
                        try:
                            require(machine.run(producer, [result, reader, output, length, mode, valid]) is None, 'void composed producer')
                        except model.Unwind as failure:
                            require(fault is not None and failure.value == machine.exception, 'unchanged composed exception')
                        else:
                            require(fault is None, 'composed unwind not swallowed')
                        output_clear = [('wipe', 'output', 0, length)] if length else []
                        expected = [('begin',)]
                        if clear_error is not None:
                            expected += [('clear-error', clear_error), ('reader', 8, 1, 0)] + cleanup + [
                                ('result', 8, 1, 4), ('result', 0, 8, 2)]
                        else:
                            expected += output_clear
                            if not active:
                                expected += [('result', 8, 1, 0), ('result', 0, 8, 2)] + output_clear
                            else:
                                expected += [('reader', 8, 1, 0), ('operation',)]
                                if fault == 'operation':
                                    expected += cleanup
                                elif fault == 'predicate':
                                    expected += [('predicate-unwind',)] + (output_clear if error is None else []) + cleanup
                                elif error is not None:
                                    expected += [('result', 0, 8, 2), ('result', 8, 1, error)] + cleanup
                                else:
                                    expected += [('reader', 8, 1, 1)] + [('result', *field) for field in
                                        ((0, 8, int(length != 0)), (8, 8, output), (16, 8, length))]
                        require(machine.events == expected, 'actual initializer composed with exact producer guard cleanup/results')
                        require(machine.load(reader, 8) == storage and machine.load(model.Pointer('reader', 8), 1) ==
                                int(active and clear_error is None and error is None and fault is None), 'composed active-state invariant')
                        visited.update(machine.visited)
                        count += 1
    expected = set()
    for name, body in merged.items():
        for label, lines in model.blocks(body).items():
            if lines == ['unreachable'] or any('16panic_in_cleanup' in line for line in lines):
                continue
            if name == producer and label == 'bb9':
                require(any('SecretRegionInitialization' in line for line in lines), 'known moved-initializer unwind arm')
                continue
            if '12as_deref_mut' in name and any(line.startswith('store ptr null,') for line in lines):
                continue
            expected.add((name, label))
    require(visited == expected, 'all selected initializer/composed-guard blocks covered')
    return count, visited, selected, merged


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in guard.final.cases(record)]
    require(len(results) == 16 and all(count == 436 for count, _, _, _ in results)
            and before == comparison.capture.sources(), 'unchanged complete debug initializer matrix')
    print('Debug output initialization + producer composition: ' + repr([(count, len(selected), len(merged))
          for count, _, selected, merged in results]) + ' PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Operation/volatile bodies opaque; clear errors and selected unwind synthetic; no whole-verifier/spill/native proof; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
