#!/usr/bin/env python3
"""Retained final-bit squeeze; secret fill/copy/mask primitives remain opaque."""
import argparse
import json
from pathlib import Path
import re

import check_debug_squeeze_operation as squeeze

model, comparison, require = squeeze.model, squeeze.comparison, squeeze.require


def closure(case):
    names, _, merged = squeeze.closure(case)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core', 'hash_core')}
    root = names['final_squeeze']
    calls = list(squeeze.decode.limit.bulk.calls(artifacts['sha3'][root]))
    for key, token in (('complete', '21complete_output_bytes'), ('bits', '17check_output_bits'),
                       ('mask', '8low_mask'), ('apply_mask', '22apply_secret_byte_mask'), ('first', '9first_mut')):
        matches = [name for name in calls if token in name]
        require(len(matches) == 1, 'unique actual final-bit helper: ' + key)
        names[key] = matches[0]
    mask = artifacts['core'][names['apply_mask']]
    require(mask.startswith('define void @') and model.parameters(mask) == ['%byte', '%keep', '%set']
            and not re.search(r'\b(?:byval|inalloca)\b', mask.splitlines()[0]), 'borrowed byte-mask primitive ABI')
    selected, pending = {}, [(root, 'sha3')]
    intrinsics = {'llvm.memcpy.p0.p0.i64', 'llvm.uadd.with.overflow.i64', 'llvm.uadd.with.overflow.i128',
                  'llvm.umul.with.overflow.i32', 'llvm.umul.with.overflow.i128', 'llvm.usub.sat.i64', 'llvm.usub.sat.i8'}
    boundaries = {names[key] for key in ('fill', 'copy', 'wipe', 'apply_mask')} | names['panics']
    panics = set(names['panics'])
    while pending:
        name, source = pending.pop()
        if name in intrinsics | boundaries or name in merged:
            continue
        if ('18panic_nounwind_fmt' in name or '24slice_end_index_len_fail' in name
                or re.fullmatch(r'_RNvNtNtC\w+_4core5slice5index16slice_index_fail', name)):
            panics.add(name)
            continue
        if name not in artifacts[source]:
            matches = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(matches) == 1, 'defined unique final-bit dependency: ' + name)
            source = matches[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed final-bit helper ABI')
        if name in selected:
            require(model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name]), 'identical shared final-bit helper')
            continue
        selected[name] = body
        pending.extend((callee, source) for callee in squeeze.decode.limit.bulk.calls(body))
    require(root in selected, 'actual final-bit body newly interpreted')
    merged.update(selected)
    return dict(names, panics=panics), selected, merged


class FinalModel(squeeze.SqueezeModel):
    def __init__(self, functions, constants, names, previous, length, valid, failure=None):
        super().__init__(functions, constants, names, previous, length, failure)
        self.total, self.valid = length, valid
        self.prefix = length if valid in (0, 8) else length - 1
        self.prefix_done = False
        self.step_limit = 120000

    def run(self, name, args, depth=0):
        if name == self.names['final_squeeze']:
            require(args == [model.Pointer('storage'), self.total, self.valid, model.Pointer('owner')],
                    'original final-bit owner, shape and initializer')
            return model.Model.run(self, name, args, depth)
        if name == self.names['squeeze']:
            require(args == [model.Pointer('storage'), model.Pointer('owner'), self.prefix], 'exact complete-byte prefix')
            self.length = self.prefix
            try:
                result = super().run(name, args, depth)
                self.prefix_done = result == self.names['success']
                return result
            finally:
                self.length = self.total
        if name == 'llvm.usub.sat.i8':
            require(len(args) == 2 and all(type(value) is int and 0 <= value <= 255 for value in args),
                    'bounded byte saturation operands')
            return max(0, args[0] - args[1])
        if name == self.names['first'] and self.failure == ('first', self.iteration, None):
            require(args == [model.Pointer('storage', 584), 168], 'original tail staging slice')
            self.events.append(('first-failure',))
            return 0
        if name == self.names['apply_mask']:
            require(self.prefix_done and self.prefix != self.total and 1 <= self.valid <= 7
                    and args == [model.Pointer('storage', 584), (1 << self.valid) - 1, 0],
                    'exact partial-byte primitive request on original staging')
            self.events.append(('mask', (1 << self.valid) - 1))
            return None
        return super().run(name, args, depth)


def expected(names, previous, length, valid, failure):
    prefix = length if valid in (0, 8) else length - 1
    events, progress, committed = [('counter-read',)], 0, False
    if previous + prefix > squeeze.decode.limit.MAXIMUM:
        return events, progress, committed, 2
    events.append(('counter-read',))
    chunks = [min(names['rate'], prefix - offset) for offset in range(0, prefix, names['rate'])]
    if not chunks:
        events.append(('counter-write',))
        committed = True
    if prefix != length:
        chunks.append(1)
    for iteration, chunk in enumerate(chunks, 1):
        tail = prefix != length and iteration == len(chunks)
        events.append(('fill', chunk))
        if failure and failure[:2] == ('fill', iteration):
            return events, progress, committed, failure[2]
        if tail:
            if failure == ('first', iteration, None):
                return events + [('first-failure',)], progress, committed, 3
            events.append(('mask', (1 << valid) - 1))
        elif failure == ('slice', iteration, None):
            return events + [('slice-failure',)], progress, committed, 3
        if failure and failure[:2] == ('write', iteration):
            return events + [('write-failure', failure[2]), ('wipe', 'storage', 584, 168)], progress, committed, 4
        events.append(('copy', chunk))
        if failure == ('copy', iteration, 'unwind'):
            return events, progress, committed, 'unwind'
        progress += chunk
        events += [('store', 16, 8, progress), ('wipe', 'storage', 584, 168)]
        if not tail and progress == prefix:
            events.append(('counter-write',))
            committed = True
    return events, progress, committed, names['success']


def inspect(case, thorough=True):
    names, selected, merged = closure(case)
    functions, constants = squeeze.begin.functions_and_constants(case, merged)
    count, visited = 0, set()
    rate, maximum = names['rate'], squeeze.decode.limit.MAXIMUM
    shapes = [(0, 0)] + [(length, valid) for length in (
        (1, rate, rate + 1, 2 * rate + 1) if thorough else (1, rate + 1)) for valid in (range(1, 9) if thorough else (1, 7, 8))]
    for length, valid in shapes:
        prefix = length if valid in (0, 8) else length - 1
        counters = (0, maximum - prefix, min(maximum, maximum - prefix + 1)) if thorough else (0, maximum)
        for previous in counters:
            failures = [None]
            # Cross every tail width/counter boundary; inject faults at every
            # iteration for representative one-byte and multichunk shapes.
            inject = not thorough or (previous == 0 and length in (1, 2 * rate + 1) and valid in (1, 7, 8))
            if previous + prefix <= maximum and inject:
                iterations = (prefix + rate - 1) // rate + int(prefix != length)
                for iteration in range(1, iterations + 1):
                    tail = prefix != length and iteration == iterations
                    failures += [('fill', iteration, error) for error in (range(5) if thorough else (0, 4))]
                    failures += [('write', iteration, error) for error in (range(4) if thorough else (0, 3))]
                    failures += [('first' if tail else 'slice', iteration, None),
                                 ('fill', iteration, 'unwind'), ('copy', iteration, 'unwind')]
            for failure in failures:
                machine = FinalModel(functions, constants, names, previous, length, valid, failure)
                machine.allocate('storage', 1040, payload=True)
                owner = machine.allocate('owner', 24)
                destination = machine.allocate('output', length, payload=True)
                machine.fields(owner, [(0, 8, destination), (8, 8, length), (16, 8, 0)])
                machine.events.clear()
                result = None
                try:
                    result = machine.run(names['final_squeeze'], [model.Pointer('storage'), length, valid, owner])
                except model.Unwind as error:
                    require(error.value == machine.exception, 'original final-bit boundary exception')
                    result = 'unwind'
                events, progress, committed, wanted = expected(names, previous, length, valid, failure)
                require(result == wanted and machine.events == events, 'exact final-bit result and prefix/tail ordering')
                require(machine.load(owner, 8) == destination and machine.load(model.Pointer('owner', 8), 8) == length
                        and machine.load(model.Pointer('owner', 16), 8) == progress, 'exact final-bit destination provenance/progress')
                value = previous + prefix if committed else previous
                require(bytes(machine.counter_bytes) == value.to_bytes(16, 'little')
                        and machine.writes == (list(enumerate(value.to_bytes(16, 'little'))) if committed else [])
                        and machine.reads == list(range(16)) * (1 if previous + prefix > maximum else 2),
                        'exact final-bit counter reads and prefix commit, including tail failure')
                visited.update(machine.visited)
                count += 1
    return count, selected, merged, visited


def main(record, shard=None):
    before = comparison.capture.sources()
    cases = list(squeeze.begin.guard.final.cases(record))
    require(len(cases) == 16 and (shard is None or shard in range(4)), 'sixteen paths and valid optional shard')
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    results = []
    for case in chosen:
        result = inspect(case)
        results.append(result)
        print('Final-bit path: ' + repr((result[0], len(result[1]), len(result[2]))) + ' PASS', flush=True)
    require(len(results) == len(chosen) and before == comparison.capture.sources(), 'complete unchanged selected final-bit matrix')
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; paths {4 * shard}..{4 * shard + 3}'))
    print('Final-bit cases: ' + str(sum(result[0] for result in results)))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Fill/copy/mask/volatile primitive bodies opaque; synthetic faults; final outer guard not composed; no erasure qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4), help='only this quarter of the matrix; all four are required')
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
