#!/usr/bin/env python3
"""Retained debug byte-squeeze scheduling; fill and byte-copy remain boundaries."""
import argparse
import json
from pathlib import Path
import re

import check_debug_counter_write as counter
import check_debug_output_write as output

decode = counter.decode
begin = decode.limit.begin
comparison, model, require = counter.comparison, counter.model, counter.require


def closure(case):
    names, _, merged = counter.closure(case)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core', 'hash_core')}
    root = names['squeeze']
    calls = list(decode.limit.bulk.calls(artifacts['sha3'][root]))
    fills = [name for name in calls if '12fill_staging' in name]
    gets = [name for name in calls if '5slice' in name and '3get' in name]
    mins = [name for name in calls if '3cmp3min' in name]
    write, copy, writes = output.closure(case.core)
    require(len(fills) == len(gets) == len(mins) == 1 and write in calls,
            'actual unique fill, staging slice, minimum and output-write helpers')
    fill = fills[0]
    require(model.parameters(artifacts['sha3'][fill]) == ['%self', '%count']
            and artifacts['sha3'][fill].startswith('define internal i8 @')
            and not re.search(r'\b(?:byval|inalloca)\b', artifacts['sha3'][fill].splitlines()[0]),
            'borrowed same-configuration fill boundary')
    minimum = re.findall(r'call i64 @' + re.escape(mins[0]) + r'\(i64 %\S+, i64 (136|168)\)', artifacts['sha3'][root])
    rate = 168 if 'Cshake128Reader' in case.root else 136
    require(minimum == [str(rate)], 'concrete sponge rate matches independent caller identity')
    selected, pending = {}, [(root, 'sha3')]
    intrinsics = {'llvm.memcpy.p0.p0.i64', 'llvm.uadd.with.overflow.i64', 'llvm.uadd.with.overflow.i128',
                  'llvm.umul.with.overflow.i32', 'llvm.usub.sat.i64'}
    boundaries = {fill, copy, names['wipe']} | names['panics']
    while pending:
        name, source = pending.pop()
        if name in intrinsics | boundaries:
            continue
        if name not in artifacts[source]:
            matches = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(matches) == 1, 'defined unique squeeze helper: ' + name)
            source = matches[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed squeeze/helper ABI')
        if name in selected:
            require(model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name]), 'identical shared squeeze helper')
            continue
        selected[name] = body
        pending.extend((callee, source) for callee in decode.limit.bulk.calls(body))
    require(all(name == copy or name in selected and model.blocks(selected[name]) == model.blocks(body)
                for name, body in writes.items()), 'actual complete output-write helper closure')
    for name, body in selected.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical composed squeeze helper')
        merged[name] = body
    return dict(names, fill=fill, staging_get=gets[0], output_write=write, copy=copy,
                rate=rate), selected, merged


class SqueezeModel(counter.WriterModel):
    def __init__(self, functions, constants, names, previous, length, failure=None):
        super().__init__(functions, constants, names, previous)
        self.length, self.failure = length, failure
        self.iteration, self.chunk = 0, 0
        self.step_limit = 80000

    def run(self, name, args, depth=0):
        if name == self.names['squeeze']:
            require(args == [model.Pointer('storage'), model.Pointer('owner'), self.length],
                    'original squeeze owner, initializer and length')
            return model.Model.run(self, name, args, depth)
        if name == 'llvm.usub.sat.i64':
            require(len(args) == 2 and all(type(value) is int and 0 <= value <= model.MASK for value in args),
                    'bounded unsigned saturating subtraction operands')
            return max(0, args[0] - args[1])
        if name == self.names['fill']:
            require(len(args) == 2 and args[0] == model.Pointer('storage')
                    and type(args[1]) is int and 1 <= args[1] <= self.names['rate'], 'original bounded fill request')
            self.iteration += 1
            self.chunk = args[1]
            self.events.append(('fill', self.chunk))
            if self.failure and self.failure[:2] == ('fill', self.iteration):
                if self.failure[2] == 'unwind':
                    raise model.Unwind(self.exception)
                return self.failure[2]
            return self.names['success']
        if name == self.names['staging_get'] and self.failure == ('slice', self.iteration, None):
            require(args == [model.Pointer('storage', 584), 168, self.chunk], 'original staging slice fault')
            self.events.append(('slice-failure',))
            return (0, model.UNKNOWN)
        if name == self.names['copy']:
            require(len(args) == 3 and args == [model.Pointer('output', self.load(model.Pointer('owner', 16), 8)),
                    model.Pointer('storage', 584), self.chunk], 'original staged copy and output progress')
            self.address(args[0], args[2], access=False)
            self.address(args[1], args[2], access=False)
            self.events.append(('copy', self.chunk))
            if self.failure == ('copy', self.iteration, 'unwind'):
                raise model.Unwind(self.exception)
            return None
        if name == self.names['output_write']:
            require(args == [model.Pointer('owner'), model.Pointer('storage', 584), self.chunk], 'original borrowed write')
            if self.failure and self.failure[:2] == ('write', self.iteration):
                self.events.append(('write-failure', self.failure[2]))
                return self.failure[2]
        return super().run(name, args, depth)


def inspect(case, thorough=True):
    names, selected, merged = closure(case)
    functions, constants = begin.functions_and_constants(case, merged)
    rate, maximum = names['rate'], decode.limit.MAXIMUM
    lengths = (0, 1, rate - 1, rate, rate + 1, 2 * rate, 2 * rate + 1) if thorough else (0, 2 * rate + 1)
    count, visited = 0, set()
    for length in lengths:
        counters = (0, (1 << 64) - 1, maximum - length, min(maximum, maximum - length + 1)) if thorough else (0, maximum)
        for previous in counters:
            failures = [None]
            if previous + length <= maximum:
                iterations = range(1, (length + rate - 1) // rate + 1) if thorough else ((2,) if length else ())
                for iteration in iterations:
                    failures += [('fill', iteration, error) for error in (range(5) if thorough else (0, 4))]
                    failures += [('write', iteration, error) for error in (range(4) if thorough else (0, 3))]
                    failures += [('slice', iteration, None), ('fill', iteration, 'unwind'), ('copy', iteration, 'unwind')]
            for failure in failures:
                machine = SqueezeModel(functions, constants, names, previous, length, failure)
                machine.allocate('storage', 1040, payload=True)
                owner = machine.allocate('owner', 24)
                destination = machine.allocate('output', length, payload=True)
                machine.fields(owner, [(0, 8, destination), (8, 8, length), (16, 8, 0)])
                machine.events.clear()
                unwinds = failure is not None and failure[2] == 'unwind'
                result = None
                try:
                    result = machine.run(names['squeeze'], [model.Pointer('storage'), owner, length])
                except model.Unwind as error:
                    require(unwinds and error.value == machine.exception, 'original squeeze-boundary exception')
                else:
                    require(not unwinds, 'squeeze exception not swallowed')
                expected, progress = [('counter-read',)], 0
                overflow = previous + length > maximum
                if not overflow:
                    for iteration, offset in enumerate(range(0, length, rate), 1):
                        chunk = min(rate, length - offset)
                        expected += [('fill', chunk)]
                        if failure and failure[:2] == ('fill', iteration):
                            break
                        if failure == ('slice', iteration, None):
                            expected += [('slice-failure',)]
                            break
                        if failure and failure[:2] == ('write', iteration):
                            expected += [('write-failure', failure[2]), ('wipe', 'storage', 584, 168)]
                            break
                        expected += [('copy', chunk)]
                        if failure == ('copy', iteration, 'unwind'):
                            break
                        progress += chunk
                        expected += [('store', 16, 8, progress), ('wipe', 'storage', 584, 168)]
                    if failure is None:
                        expected += [('counter-write',)]
                require(machine.events == expected, 'exact per-chunk write/clear order and success-only counter commit')
                expected_error = 2 if overflow else names['success'] if failure is None else (
                    failure[2] if failure[0] == 'fill' else 3 if failure[0] == 'slice' else 4)
                require(unwinds or result == expected_error, 'exact squeeze result')
                require(machine.load(owner, 8) == destination and machine.load(model.Pointer('owner', 8), 8) == length
                        and machine.load(model.Pointer('owner', 16), 8) == progress, 'original output owner and exact initialized prefix')
                committed = not overflow and failure is None
                value = previous + length if committed else previous
                require(bytes(machine.counter_bytes) == value.to_bytes(16, 'little')
                        and machine.writes == (list(enumerate(value.to_bytes(16, 'little'))) if committed else [])
                        and machine.reads == list(range(16)), 'exact counter value, reads and commit stores')
                visited.update(machine.visited)
                count += 1
    return count, selected, merged, visited


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in begin.guard.final.cases(record)]
    require(len(results) == 16 and before == comparison.capture.sources(), 'complete unchanged debug squeeze matrix')
    print('Debug squeeze: ' + repr([(count, len(selected), len(merged)) for count, selected, merged, _ in results]) + ' PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Fill/copy/volatile bodies remain boundaries; helper faults synthetic; no scalar/spill/native erasure proof or rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
