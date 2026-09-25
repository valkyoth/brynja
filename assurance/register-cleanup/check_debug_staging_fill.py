#!/usr/bin/env python3
"""Inspect retained debug staging geometry and borrowed primitive handoffs."""
import argparse
import json
from pathlib import Path
import re

import check_debug_squeeze_guard as guard
import check_sha3_fill as oracle
from check_recorded_keccak import constants as round_constants

model, require, comparison = guard.model, guard.require, guard.comparison


def closure(case):
    names, _, _ = guard.squeeze.closure(case)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core', 'hash_core')}
    unique = lambda source, token: oracle.shared.unique(artifacts[source], token)
    names = dict(names, scalar=unique('sha3', '11permutation6native6scalar'),
                 transfer=unique('core', 'secret_memory_transfer10copy_bytes'),
                 copy_region=unique('core', '18copy_secret_region'))
    for source, name, arity in (('sha3', names['scalar'], 5), ('core', names['transfer'], 3), ('core', names['wipe'], 2)):
        body = artifacts[source][name]
        require(body.startswith('define internal void @') and len(model.parameters(body)) == arity
                and not re.search(r'\b(?:byval|inalloca)\b', body.splitlines()[0]),
                'defined borrowed void primitive ABI')
    native = artifacts['sha3'][unique('sha3', '11permutation6native7permute')]
    scalar_calls = [line for line in native.splitlines() if re.search(r'\bcall void @' + re.escape(names['scalar']) + r'\(', line)]
    require(len(scalar_calls) == 1, 'one actual scalar handoff')
    args = comparison.arguments(scalar_calls[0], re.search(comparison.SYMBOL, scalar_calls[0]).end())
    require(len(args) == 5, 'four borrowed operands and public round table')
    table = re.fullmatch(r'ptr align 8 (@[-.$\w]+)', args[-1])
    require(table is not None, 'original immutable scalar round table')
    constants = re.findall(r'^' + re.escape(table[1]) + r' = private unnamed_addr constant \[192 x i8\] c"((?:\\[0-9A-F]{2})+)"(?:, align 8)$',
                           case.sha3, re.M)
    require(len(constants) == 1 and bytes.fromhex(constants[0].replace('\\', '')) == round_constants(),
            'exact independent-oracle round constants')
    names['table'] = model.Pointer(table[1])
    boundaries = {names['scalar'], names['transfer'], names['wipe']}
    intrinsics = {'llvm.memcpy.p0.p0.i64', 'llvm.uadd.with.overflow.i64', 'llvm.usub.with.overflow.i64'}
    pending, selected, panics = [(names['fill'], 'sha3')], {}, set()
    while pending:
        name, source = pending.pop()
        if name in boundaries | intrinsics:
            continue
        if 'panic' in name:
            panics.add(name)
            continue
        if name not in artifacts[source]:
            matches = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(matches) == 1, 'unique same-configuration staging helper: ' + name)
            source = matches[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed staging/helper ABI')
        if name in selected:
            require(model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name]), 'identical shared staging helper')
            continue
        selected[name] = body
        pending.extend((callee, source) for callee in guard.squeeze.decode.limit.bulk.calls(body))
    require(names['copy_region'] in selected, 'actual length-checking core copy wrapper included')
    return dict(names, panics=panics), selected


class FillModel(model.Model):
    def __init__(self, functions, constants, names, cursor, failed_copy=0, unwind=None):
        super().__init__(functions, constants, '')
        self.names, self.cursor = names, cursor
        self.failed_copy, self.unwind = failed_copy, unwind
        self.copies = 0
        self.exception = (model.Pointer('exception', 7), 19)
        self.step_limit = 30000

    def load(self, ptr, width):
        if ptr == model.Pointer('storage', 1039) and width == 1:
            self.address(ptr, width, access=False)
            return self.cursor
        return super().load(ptr, width)

    def store(self, ptr, width, value):
        if ptr == model.Pointer('storage', 1039) and width == 1:
            require(type(value) is int and 0 <= value <= 255, 'bounded cursor byte')
            self.address(ptr, width, access=False)
            self.cursor = value
            self.events.append(('cursor', value))
            return
        return super().store(ptr, width, value)

    def run(self, name, args, depth=0):
        if name == 'llvm.usub.with.overflow.i64':
            require(len(args) == 2 and all(type(x) is int and 0 <= x <= model.MASK for x in args),
                    'bounded checked subtraction operands')
            return ((args[0] - args[1]) & model.MASK, int(args[0] < args[1]))
        if name == self.names['scalar']:
            require(args == [model.Pointer('storage', n) for n in (48, 752, 792, 832)] + [self.names['table']],
                    'original permutation state and scratch borrows')
            self.events.append(('permute',))
            if self.unwind == 'permute':
                raise model.Unwind(self.exception)
            return None
        if name == self.names['wipe']:
            require(args in [[model.Pointer('storage', offset), size] for offset, size in ((752, 40), (792, 40), (832, 200))],
                    'complete permutation scratch clear')
            self.address(args[0], args[1], access=False)
            self.events.append(('clear', args[0].offset, args[1]))
            return None
        if name == self.names['copy_region']:
            require(len(args) == 4 and args[1] == args[3] and type(args[1]) is int and 0 < args[1] <= 168
                    and all(isinstance(args[i], model.Pointer) and args[i].region == 'storage' for i in (0, 2))
                    and 584 <= args[0].offset <= 752 - args[1]
                    and 48 <= args[2].offset <= 48 + self.names['rate'] - args[1], 'bounded state-to-staging copy')
            self.copies += 1
            self.events.append(('copy', args[0].offset, args[2].offset, args[1]))
            if self.copies == self.failed_copy:
                return 2
        if name == self.names['transfer']:
            require(len(args) == 3 and all(isinstance(args[i], model.Pointer) and args[i].region == 'storage' for i in (0, 1))
                    and ('copy', args[0].offset, args[1].offset, args[2]) == self.events[-1],
                    'unchanged original borrowed copy-byte handoff')
            self.address(args[0], args[2], access=False)
            self.address(args[1], args[2], access=False)
            self.events.append(('transfer',))
            if self.unwind == ('copy', self.copies):
                raise model.Unwind(self.exception)
            return None
        if name == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[2] in (16, 24) and args[3] == 0, 'complete nonvolatile result descriptor copy')
            destination, source, length, _ = args
            self.address(source, length)
            self.address(destination, length)
            require(source.region != destination.region, 'nonoverlapping metadata descriptors')
            fields = [(ptr.offset - source.offset, width, value) for ptr, (width, value) in self.memory.items()
                      if ptr.region == source.region and source.offset <= ptr.offset < source.offset + length]
            require(all(offset + width <= length for offset, width, _ in fields), 'whole typed descriptor fields')
            for offset, width, value in fields:
                self.store(model.Pointer(destination.region, destination.offset + offset), width, value)
            return None
        return super().run(name, args, depth)


def scenarios(rate, thorough):
    yield from ((count, cursor, failed, None) for count, cursor, failed in (oracle.scenarios(rate) if thorough else
                ((n, p, failure) for n in (0, 1, 168, 169) for p in (0, rate - 1, rate, 255) for failure in (0, 1, 2))))
    for count in (1, rate, 168):
        for cursor in (0, rate - 1, rate):
            yield count, cursor, 0, 'permute'
            yield count, cursor, 0, ('copy', 1)
            yield count, cursor, 0, ('copy', 2)


def expected(rate, count, cursor, old, failed_copy, unwind):
    result, final_cursor, events = oracle.expected(rate, count, cursor, old, failed_copy)
    expected, copies, actual_cursor = [], 0, cursor
    for event in events:
        expected.append(event)
        if event[0] == 'cursor':
            actual_cursor = event[1]
        if event[0] == 'permute' and unwind == 'permute':
            return None, actual_cursor, expected, True
        if event[0] == 'copy':
            copies += 1
            if copies != failed_copy:
                expected.append(('transfer',))
                if unwind == ('copy', copies):
                    return None, actual_cursor, expected, True
    return result, final_cursor, expected, False


def inspect(case, thorough=True):
    names, selected = closure(case)
    functions, constants = guard.begin.functions_and_constants(case, selected)
    old = names['success'] == 5
    count, visited = 0, set()
    for length, cursor, failed, unwind in scenarios(names['rate'], thorough):
        machine = FillModel(functions, constants, names, cursor, failed, unwind)
        storage = machine.allocate('storage', 1040, payload=True)
        value, did_unwind = None, False
        try:
            value = machine.run(names['fill'], [storage, length])
        except model.Unwind as error:
            require(error.value == machine.exception, 'original staging primitive exception propagates')
            did_unwind = True
        wanted, final_cursor, events, wanted_unwind = expected(names['rate'], length, cursor, old, failed, unwind)
        require((value, machine.cursor, machine.events, did_unwind) == (wanted, final_cursor, events, wanted_unwind),
                'exact staging geometry, copy/clear ordering, cursor commit and result: '
                + repr((length, cursor, failed, unwind)) + '; actual=' + repr((value, machine.cursor, machine.events, did_unwind)))
        visited.update(machine.visited)
        count += 1
    return count, selected, visited


def main(record, shard=None):
    before = comparison.capture.sources()
    cases = list(guard.begin.guard.final.cases(record))
    require(len(cases) == 16 and (shard is None or shard in range(4)), 'sixteen retained paths and valid shard')
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    counts = []
    for case in chosen:
        count, selected, _ = inspect(case)
        counts.append(count)
        print(f'Debug staging fill: {count} cases; {len(selected)} functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured sources unchanged')
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print('Staging geometry cases: ' + str(sum(counts)))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Scalar/copy/volatile bodies opaque; no outer-guard, whole-call, register/spill or native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
