#!/usr/bin/env python3
"""Retained checked output-limit arithmetic and empty-operation composition."""
import argparse
import json
from pathlib import Path
import re

import check_debug_producer_operation as operation

begin = operation.begin
comparison, model, require, bulk = operation.comparison, operation.model, operation.require, operation.bulk
MAXIMUM = (1 << 128) - 1


def closure(case):
    producer, names, _, guarded = operation.closure(case)
    definitions = comparison.definitions(case.sha3)
    root = names['empty_check']
    selected, pending, decoders = {}, [root], set()
    while pending:
        name = pending.pop()
        if name == 'llvm.uadd.with.overflow.i128':
            continue
        require(name in definitions, 'defined same-configuration output-limit helper')
        body = definitions[name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed counter/check helper ABI')
        if '12read_counter' in name:
            header = body.splitlines()[0]
            args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
            require(header.startswith('define i128 @') and len(args) == 1
                    and comparison.pointer(args[0]) == '%bytes', 'actual borrowed counter decoder ABI')
            decoders.add(name)
            continue
        if name in selected:
            continue
        selected[name] = body
        pending.extend(bulk.calls(body))
    additions = [name for name in selected if '11checked_add' in name]
    require(len(selected) == 6 and len(decoders) == len(additions) == 1,
            'six-function limit closure with actual checked arithmetic and one counter boundary')
    merged = dict(guarded)
    for name, body in selected.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'same composed limit helper')
        merged[name] = body
    require(len(merged) == len(guarded) + 6, 'complete operation/limit composition')
    return producer, dict(names, counter=decoders.pop(), addition=additions[0]), selected, merged


class LimitModel(operation.OperationModel):
    def __init__(self, functions, constants, names, counter, active=1, mode=0, unwind=False):
        valid = model.UNKNOWN if mode == 0 else 0
        super().__init__(functions, constants, names, 0, active, mode, valid, None, None, None, False)
        self.counter_value, self.counter_unwind = counter, unwind

    def run(self, name, args, depth=0):
        if name == self.names['empty_check']:
            return model.Model.run(self, name, args, depth)
        if name == self.names['counter']:
            require(args == [model.Pointer('storage', 16)], 'original exact 16-byte output counter field')
            self.address(args[0], 16, access=False)
            self.events.append(('counter-read',))
            if self.counter_unwind:
                raise model.Unwind(self.exception)
            return self.counter_value
        return super().run(name, args, depth)


def values(thorough):
    return (0, 1, 7, (1 << 64) - 1, 1 << 64, (1 << 64) + 1,
            (1 << 127) - 1, 1 << 127, (1 << 127) + 1, MAXIMUM - 1, MAXIMUM) if thorough else (
                0, 1, (1 << 64) - 1, 1 << 64, MAXIMUM - 1, MAXIMUM)


def inspect(case, thorough=True):
    producer, names, selected, merged = closure(case)
    functions, constants = begin.functions_and_constants(case, merged)
    count, visited = 0, set()
    for counter in values(thorough):
        for increment in values(thorough):
            # The limit adapter discards a successful sum. Bind the actual
            # helper's value as well, rather than testing its tag alone.
            machine = LimitModel(functions, constants, names, counter)
            destination = machine.allocate('result', 32)
            require(machine.run(names['addition'], [destination, counter, increment]) is None, 'void checked-add result')
            fits = counter + increment <= MAXIMUM
            require(machine.load(destination, 16) == int(fits)
                    and machine.load(model.Pointer('result', 16), 16) == (counter + increment if fits else model.UNKNOWN),
                    'exact full-width sum or None with undefined inactive payload')
            require(len(machine.events) == 2 and all(event[0] == 'result' for event in machine.events),
                    'checked addition only writes its result descriptor')
            visited.update(machine.visited)
            count += 1
            machine = LimitModel(functions, constants, names, counter)
            owner = machine.allocate('storage', 1040, payload=True)
            result = machine.run(names['empty_check'], [owner, increment])
            require(result == int(counter + increment > MAXIMUM), 'exact non-mutating 128-bit overflow result')
            require(machine.events == [('counter-read',)], 'one original counter read and no owner mutation')
            visited.update(machine.visited)
            count += 1
        for active in (0, 1):
            for mode in (0, 1):
                for unwind in (False, True) if active else (False,):
                    machine = LimitModel(functions, constants, names, counter, active, mode, unwind)
                    result = machine.allocate('result', 24)
                    reader = machine.allocate('reader', 16)
                    storage = machine.allocate('storage', 1040, payload=True)
                    output = machine.allocate('output', 0, payload=True)
                    machine.fields(reader, [(0, 8, storage), (8, 1, active)])
                    machine.events.clear()
                    try:
                        require(machine.run(producer, [result, reader, output, 0, mode, machine.valid]) is None, 'void empty producer')
                    except model.Unwind as error:
                        require(unwind and error.value == machine.exception, 'original synthetic counter exception')
                    else:
                        require(not unwind, 'counter exception not swallowed')
                    expected = [('begin',)]
                    if not active:
                        expected += [('result', 8, 1, 0), ('result', 0, 8, 2)]
                    else:
                        expected += [('reader', 8, 1, 0), ('operation',), ('counter-read',)]
                        if unwind:
                            expected += [('wipe', 'storage', offset, width) for offset, width in begin.guard.final.regions()]
                        else:
                            expected += [('finish',), ('reader', 8, 1, 1), ('result', 0, 8, 0)]
                    require(machine.events == expected, 'actual zero-increment admission and composed guard/completion cleanup')
                    require(machine.load(reader, 8) == storage and machine.load(model.Pointer('reader', 8), 1) == int(active and not unwind),
                            'original owner and correct empty-operation active state')
                    visited.update(machine.visited)
                    count += 1
    expected = {(name, label) for name, body in selected.items() for label, lines in model.blocks(body).items()
                if lines != ['unreachable']}
    require({item for item in visited if item[0] in selected} == expected, 'all limit/helper blocks except unreachable covered')
    return count, selected, merged, visited


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in begin.guard.final.cases(record)]
    require(len(results) == 16 and all(count == 308 for count, _, _, _ in results)
            and before == comparison.capture.sources(), 'complete unchanged limit matrix')
    print('Debug output limits: ' + repr([(count, len(merged)) for count, _, merged, _ in results]) + ' PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Counter decoder/volatile bodies opaque; counter unwind synthetic; no scalar-copy/spill/native erasure proof; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
