#!/usr/bin/env python3
"""Retained accelerated engine admission/counter bodies, standalone and composed."""
import argparse
import json
from pathlib import Path
import re

import check_debug_accelerated_bridges as bridges
import check_debug_counter_decode as decode

operation = bridges.operation
model, require, comparison = bridges.model, bridges.require, bridges.comparison
MAXIMUM = (1 << 128) - 1


def closure(case, consuming):
    root, producer, names, outer, merged = bridges.closure(case, consuming)
    artifacts = {key: comparison.definitions(getattr(case, key))
                 for key in ('sha3', 'core', 'hash_core')}
    selected, pending, panics, sessions = {}, [(names['preflight'], 'sha3')], set(), set()
    intrinsics = {'llvm.memcpy.p0.p0.i64', 'llvm.uadd.with.overflow.i64',
                  'llvm.uadd.with.overflow.i128', 'llvm.umul.with.overflow.i64'}
    while pending:
        name, source = pending.pop()
        if name in intrinsics:
            continue
        if re.search(r'24panic_const_(?:shl|add)_overflow', name):
            panics.add(name)
            continue
        if '13KeccakSession5check' in name:
            declarations = [line for line in case.sha3.splitlines()
                            if line.startswith('declare i8 @') and name + '(' in line]
            require(len(declarations) == 1 and not re.search(r'\b(?:byval|inalloca)\b', declarations[0]),
                    'one borrowed session-check declaration')
            args = comparison.arguments(declarations[0], re.search(comparison.SYMBOL, declarations[0]).end())
            require(len(args) == 1 and args[0].startswith('ptr '), 'session check pointer-only ABI')
            sessions.add(name)
            continue
        if name not in artifacts[source]:
            sources = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(sources) == 1, 'same-row unambiguous engine dependency: ' + name)
            source = sources[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed preflight/helper ABI')
        if name in selected:
            require(model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name]), 'identical preflight helper')
            continue
        selected[name] = body
        pending.extend((callee, source) for callee in bridges.bulk.calls(body))
    counters = [name for name in selected if 'engine10read_count' in name]
    multipliers = [name for name in selected if '14saturating_mul' in name]
    require(len(counters) == len(multipliers) == len(sessions) == 1 and len(panics) == 2,
            'one actual decoder/multiplier/session boundary and two forbidden panics')
    for name, body in selected.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical engine/outer shared helper')
        merged[name] = body
    names.update(counter=counters[0], multiply=multipliers[0], session=sessions.pop(),
                 panics=panics, session_success=7 if case.compiler == '1.90.0' else 255)
    return root, producer, names, selected, merged


class PreflightModel(bridges.BridgedOperation):
    def __init__(self, functions, constants, names, length, mode, valid, producer,
                 counter, failed, squeezing, session, direct=False):
        super().__init__(functions, constants, names, length, mode, valid, None, producer)
        self.counter_bytes = counter.to_bytes(16, 'little')
        self.failed, self.squeezing, self.session_result = failed, squeezing, session
        self.direct, self.in_preflight, self.decoding = direct, False, False
        self.reads, self.decoded, self.engine_events, self.preflight_calls = [], [], [], 0

    def load(self, ptr, width):
        if isinstance(ptr, model.Pointer) and ptr.region == 'storage':
            require(self.in_preflight, 'engine metadata read only during actual preflight')
            self.address(ptr, width, access=False)
            if ptr.offset in (858, 859) and width == 1 and not self.decoding:
                self.engine_events.append(('state-read', ptr.offset))
                return self.squeezing if ptr.offset == 858 else self.failed
            require(self.decoding and width == 1 and 640 <= ptr.offset < 656,
                    'decoder reads only sixteen original output-counter bytes')
            self.reads.append(ptr.offset - 640)
            return self.counter_bytes[ptr.offset - 640]
        return super().load(ptr, width)

    def store(self, ptr, width, value):
        require(not self.in_preflight or ptr.region != 'storage', 'preflight never changes engine storage')
        return super().store(ptr, width, value)

    def run(self, name, args, depth=0):
        if name in self.names['panics']:
            raise ValueError('bounded preflight decoder cannot enter panic boundary')
        if name == self.names['preflight']:
            require(not self.in_preflight and args == [model.Pointer('storage'), self.length],
                    'one nonrecursive original engine/request preflight')
            if not self.direct:
                self.armed()
            self.events.append(('preflight',))
            self.preflight_calls += 1
            self.in_preflight = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.in_preflight = False
        if name == self.names['session']:
            require(self.in_preflight and not self.decoding and args == [model.Pointer('storage')],
                    'original engine session checked before counter decoding')
            self.engine_events.append(('session',))
            if self.session_result == 'unwind':
                raise model.Unwind(self.exception)
            return self.session_result
        if name == self.names['counter']:
            require(self.in_preflight and not self.decoding and args == [model.Pointer('storage', 640)],
                    'original counter field; no recursive decoding')
            self.engine_events.append(('counter',))
            self.decoding = True
            try:
                value = model.Model.run(self, name, args, depth)
                self.decoded.append(value)
                return value
            finally:
                self.decoding = False
        if self.in_preflight and name == 'llvm.memcpy.p0.p0.i64':
            # This is an actual iterator/result descriptor copy, not payload.
            return operation.guard.portable.GuardModel.run(self, name, args, depth)
        return super().run(name, args, depth)


def expected(counter, length, failed, squeezing, session, success):
    events = [('state-read', 859)]
    if not failed:
        events.append(('state-read', 858))
    if failed or not squeezing:
        return 7, events, []
    events.append(('session',))
    if session == 'unwind' or session != success:
        return session, events, []
    events.append(('counter',))
    return 8 if counter + length > MAXIMUM else None, events, list(range(16))


def scenarios(thorough, success):
    # All one-bit counter basis values plus nonuniform bytes exercise decoding;
    # large increments distinguish full-width admission from truncation.
    for counter in decode.values(thorough) + [MAXIMUM - 1, MAXIMUM - model.MASK, MAXIMUM - model.MASK + 1]:
        for length in (0, 1, 169, model.MASK):
            yield counter, length, 0, 1, success
    for counter in (0, MAXIMUM):
        for length in (0, 169):
            for failed, squeezing in ((0, 0), (1, 0), (1, 1), (0, 1)):
                for session in (*range(7), success, 'unwind'):
                    yield counter, length, failed, squeezing, session


def inspect(case, thorough=True, consuming=True):
    root, producer, names, selected, merged = closure(case, consuming)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in merged.items()}
    constants = '\n'.join(dict.fromkeys(line for text in (case.sha3, case.core, case.hash_core, case.kmac)
                                      for line in text.splitlines() if line.startswith(('@anon.', '@alloc_'))))
    count, composed, visited = 0, 0, set()
    for counter, length, failed, squeezing, session in scenarios(thorough, names['session_success']):
        # Huge lengths are arithmetic probes, not enormous output allocations.
        modes = (True, False) if length <= 169 else (True,)
        for direct in modes:
            mode, valid = int(consuming), (7 if length else 0) if consuming else model.UNKNOWN
            machine = PreflightModel(functions, constants, names, length, mode, valid, producer,
                                     counter, failed, squeezing, session, direct)
            storage = machine.allocate('storage', 1088, payload=True)
            if not direct:
                result = machine.allocate('result', 24)
                reader = machine.allocate('entry-reader', 8)
                output = machine.allocate('output', length, payload=True)
                machine.fields(reader, [(0, 8, storage)])
            machine.events.clear()
            error, engine_events, reads = expected(counter, length, failed, squeezing, session, names['session_success'])
            unwound, returned = False, None
            try:
                returned = machine.run(names['preflight'], [storage, length]) if direct else machine.run(
                    root, [result, reader, output, length] + ([valid] if consuming else []))
            except model.Unwind as exception:
                require(exception.value == machine.exception, 'exact original session exception')
                unwound = True
            require(machine.engine_events == engine_events and machine.reads == reads
                    and machine.decoded == ([counter] if reads else []) and machine.preflight_calls == 1
                    and not machine.in_preflight and not machine.decoding and unwound == (error == 'unwind'),
                    'exact state/session/counter ordering and original unwind')
            if direct:
                require((unwound or returned == (names['success'] if error is None else error))
                        and machine.events == [('preflight',)], 'read-only actual preflight result')
            else:
                failure = None if error is None else ('preflight', 0, error)
                inner, progress, success = operation.expected(length, mode, valid, failure)
                cleanup = [('state', 859, 1, 1), ('state', 616, 8, 0)] + [
                    ('wipe', 'storage', offset, width) for offset, width in
                    ((656, 200), (624, 16), (640, 16), (856, 2), (864, 168), (1056, 2))]
                trace = [('producer-enter',)] + inner + [('producer-exit',)] + (cleanup if consuming else [])
                if not unwound:
                    if success:
                        fields = ((8, 8, output), (16, 8, length), (0, 8, 1)) if length else ((0, 8, 0),)
                        trace += [('outer-descriptor',)] + [('result', *field) for field in fields] + [('outer-descriptor',)]
                    else:
                        trace += [('result', 8, 1, error), ('result', 0, 8, 2)]
                require(returned is None and machine.events == trace and machine.progress == progress
                        and machine.producer_calls == 1 and machine.guard_stores == ([0, 1] if success else [0]),
                        'actual preflight composes with original output/owner cleanup and result identity')
                composed += 1
            visited.update(machine.visited)
            count += 1
    # Probe actual saturation helper separately; such offsets cannot arise from
    # this sixteen-byte decoder. Do not misrepresent them as reachable inputs.
    for a, b in ((0, 8), (15, 8), (model.MASK // 8, 8), (model.MASK // 8 + 1, 8), (model.MASK, model.MASK)):
        machine = PreflightModel(functions, constants, names, 0, 0, model.UNKNOWN, producer, 0, 0, 1, names['session_success'], True)
        require(machine.run(names['multiply'], [a, b]) == min(a * b, model.MASK), 'actual bounded saturating multiplication')
        require(not machine.events and not machine.engine_events and not machine.reads, 'scalar helper has no owner effects')
        visited.update(machine.visited)
        count += 1
    for name, body in selected.items():
        graph = model.blocks(body)
        reachable, pending = set(), ['start']
        while pending:
            label = pending.pop()
            require(label in graph, 'defined preflight helper successor')
            if label in reachable or any(panic in line for panic in names['panics'] for line in graph[label]):
                continue
            require(graph[label] != ['unreachable'], 'no reachable unqualified unreachable block')
            reachable.add(label)
            pending.extend(re.findall(r'label %(\S+?)(?:,|\s|$)', '\n'.join(graph[label])))
        require({label for function, label in visited if function == name} == reachable,
                'all preflight/helper normal blocks exercised: ' + name)
    return count, composed, selected, merged, visited


def main(record, shard):
    before = comparison.capture.sources()
    cases = list(operation.cases(record))
    require(len(cases) == 8, 'eight source-bound accelerated debug paths')
    for case in cases if shard is None else [cases[shard]]:
        for consuming in (False, True):
            count, composed, selected, merged, _ = inspect(case, consuming=consuming)
            print(f'Accelerated preflight {consuming=}: {count} cases; {composed} composed; '
                  f'{len(selected)} preflight/{len(merged)} total functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all 8 paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Session/read/copy/mask/volatile bodies opaque; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
