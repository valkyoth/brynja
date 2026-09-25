#!/usr/bin/env python3
"""Compose retained accelerated initialization, chunk dispatch, completion and guards."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re

import check_debug_accelerated_guard as guard
import check_debug_output_finish as finish
import check_debug_fips202_output as constructor

comparison, model, require, bulk = guard.comparison, guard.model, guard.require, guard.bulk


@dataclass(frozen=True)
class Case(guard.final.Case):
    hash_core: str


def cases(record):
    supplemental = {}
    for row, _, _, _ in comparison.cases(record):
        if row['profile'] != 'debug' or row['mode'] != 'accelerated':
            continue
        paths = [Path(path) for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'same-row SHA-3 dependency')
        text = (record.parent / paths[0]).read_text()
        require(text not in supplemental, 'unique row for supplemental hash-core helpers')
        supplemental[text] = constructor.supplemental(record, paths[0])
    for case in guard.final.cases(record):
        yield Case(**vars(case), hash_core=supplemental[case.sha3])


def closure(case):
    root, names, guarded = guard.closure(case)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core', 'hash_core', 'kmac')}
    operation = artifacts['sha3'][names['operation']]
    roles = [('preflight', '9preflight'), ('read', '6Engine4read'), ('mask', '22apply_secret_byte_mask'),
             ('finish', '13finish_secret'), ('write', '26SecretRegionInitialization5write'),
             ('slice', '7get_mut'), ('last', '8last_mut'), ('as_mut', '6as_mut'), ('subtract', '11checked_sub')]
    for role, token in roles:
        matches = [name for name in bulk.calls(operation) if token in name]
        require(len(matches) == 1, 'unique actual accelerated operation helper: ' + role)
        names[role] = matches[0]
    copies = [name for name in artifacts['core'] if 'secret_memory_transfer10copy_bytes' in name]
    require(len(copies) == 1, 'one actual core copy boundary')
    names['copy'] = copies[0]
    boundaries = {names[key] for key in ('preflight', 'read', 'mask', 'copy', 'wipe')}
    for role, types in (('preflight', ('ptr', 'i64')), ('read', ('ptr', 'ptr', 'i64')),
                        ('mask', ('ptr', 'i8', 'i8')), ('copy', ('ptr', 'ptr', 'i64'))):
        matches = [definitions[names[role]] for definitions in artifacts.values() if names[role] in definitions]
        require(len(matches) == 1, 'defined actual primitive boundary: ' + role)
        header = matches[0].splitlines()[0]
        args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
        require(len(args) == len(types) and not re.search(r'\b(?:byval|inalloca)\b', header)
                and all(arg.startswith(kind + ' ') for arg, kind in zip(args, types))
                and header.startswith('define ' + ('internal i8' if role in ('preflight', 'read') else 'internal void' if role == 'copy' else 'void') + ' @'),
                'borrowed primitive boundary ABI: ' + role)
    selected, owners = {}, {}
    pending = [(root, 'sha3')]
    while pending:
        name, source = pending.pop()
        if name in boundaries or name.startswith('llvm.') or 'panicking' in name:
            continue
        if name not in artifacts[source]:
            sources = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(sources) == 1, 'unambiguous actual operation dependency: ' + name)
            source = sources[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed operation/helper ABI')
        if name in selected:
            require(owners[name] == source or (model.parameters(body) == model.parameters(selected[name])
                    and model.blocks(body) == model.blocks(selected[name])), 'identical shared helper')
            continue
        selected[name], owners[name] = body, source
        pending.extend((callee, source) for callee in bulk.calls(body))
    _, completion_names, completed = finish.closure(case.core)
    for name, body in {**guarded, **completed}.items():
        if name == names['wipe']:
            continue
        require(name in selected and model.parameters(body) == model.parameters(selected[name])
                and model.blocks(body) == model.blocks(selected[name]), 'original guard/completion closure included')
    clears = [name for name in selected if '18clear_owned_region' in name]
    require(len(clears) == 1, 'one actual region-clearing wrapper')
    names.update(completion_names, clear=clears[0], success=12 if case.compiler == '1.90.0' else 255)
    return root, names, selected


class OperationModel(guard.GuardModel):
    def __init__(self, functions, constants, names, length, mode, valid, failure):
        super().__init__(functions, constants, names, length, mode, valid, None, None, None)
        self.failure, self.inside_begin, self.inside_operation = failure, False, False
        self.iteration, self.progress, self.chunk, self.initializer = 0, 0, 0, None
        self.inside_finish = False
        self.step_limit = 150000
        for line in constants.splitlines():
            match = re.fullmatch(r'(@[-.$\w]+) = private unnamed_addr constant \[3 x i8\] c"((?:\\[0-9A-Fa-f]{2}){3})", align 1', line)
            if match:
                self.allocate(match[1], 3)
                for offset, byte in enumerate(re.findall(r'\\([0-9A-Fa-f]{2})', match[2])):
                    self.memory[model.Pointer(match[1], offset)] = (1, int(byte, 16))

    def armed(self):
        require(self.in_guard and self.inside_operation and self.guard_pointer is not None
                and self.load(self.guard_pointer, 8) == model.Pointer('storage')
                and self.load(model.Pointer(self.guard_pointer.region, 8), 1) == 0,
                'original storage remains under armed accelerated guard')

    def store(self, ptr, width, value):
        super().store(ptr, width, value)
        if self.initializer is not None and ptr == model.Pointer(self.initializer.region, self.initializer.offset + 16):
            require(width == 8 and type(value) is int and 0 <= value <= self.length, 'bounded initializer progress')
            self.progress = value
            self.events.append(('progress', value))

    def run(self, name, args, depth=0):
        if name == self.names['begin']:
            require(args[1:] == [model.Pointer('output'), self.length] and not self.in_guard, 'original destination before guard')
            self.events.append(('begin',))
            self.inside_begin = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.inside_begin = False
        if name == self.names['clear'] and self.inside_begin and self.failure and self.failure[0] == 'clear':
            require(args == [model.Pointer('output'), self.length] and self.length > 0, 'original clearing failure boundary')
            self.events.append(('clear-error', self.failure[2]))
            return self.failure[2]
        if name == self.names['operation']:
            require(len(args) == 3 and isinstance(args[1], model.Pointer)
                    and args[2] == model.Pointer('storage') and not self.inside_operation, 'original operation storage')
            self.inside_operation = True
            self.armed()
            at = lambda offset, width: self.load(model.Pointer(args[1].region, args[1].offset + offset), width)
            require(at(0, 8) == int(self.length != 0), 'original initializer presence')
            if self.length:
                require((at(8, 8), at(16, 8), at(24, 8)) == (model.Pointer('output'), self.length, 0), 'whole original initializer')
            valid, length = at(32, 8), at(40, 8)
            require(self.load(length, 8) == self.length and self.load(valid, 1) == self.mode
                    and self.load(model.Pointer(valid.region, valid.offset + 1), 1) == self.valid, 'original shape captures')
            self.events.append(('operation',))
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.inside_operation = False
        if name == self.names['preflight']:
            self.armed()
            require(args == [model.Pointer('storage'), self.length], 'original preflight request')
            self.events.append(('preflight',))
            if self.failure and self.failure[0] == 'preflight':
                if self.failure[2] == 'unwind':
                    raise model.Unwind(self.exception)
                return self.failure[2]
            return self.names['success']
        if name == self.names['slice']:
            self.armed()
            self.iteration += 1
            self.chunk = min(168, self.length - self.progress)
            require(args == [model.Pointer('storage', 864), 168, self.chunk] and self.chunk > 0, 'bounded original staging chunk')
        if name in (self.names['slice'], self.names['last'], self.names['as_mut'], self.names['subtract']):
            role = next(key for key in ('slice', 'last', 'as_mut', 'subtract') if self.names[key] == name)
            if self.failure == (role, self.iteration, None):
                self.events.append(('missing', role))
                return (0, model.UNKNOWN) if role in ('slice', 'subtract') else 0
        if name in (self.names['read'], self.names['mask'], self.names['copy']):
            self.armed()
            role = next(key for key in ('read', 'mask', 'copy') if self.names[key] == name)
            if role == 'read':
                require(args == [model.Pointer('storage'), model.Pointer('storage', 864), self.chunk], 'original engine and staging slice')
                self.events.append(('read', self.chunk))
            elif role == 'mask':
                require(self.mode == 1 and self.progress + self.chunk == self.length
                        and args == [model.Pointer('storage', 864 + self.chunk - 1), 255 >> (8 - self.valid), 0], 'final-only exact mask')
                self.events.append(('mask', self.valid))
            else:
                require(args == [model.Pointer('output', self.progress), model.Pointer('storage', 864), self.chunk], 'original destination prefix and staging')
                self.address(args[0], args[2], access=False)
                self.address(args[1], args[2], access=False)
                self.events.append(('copy', self.chunk))
            if self.failure and self.failure[:2] == (role, self.iteration):
                if self.failure[2] == 'unwind':
                    raise model.Unwind(self.exception)
                return self.failure[2]
            return self.names['success'] if role == 'read' else None
        if name == self.names['write']:
            self.armed()
            require(len(args) == 3 and isinstance(args[0], model.Pointer)
                    and args[1:] == [model.Pointer('storage', 864), self.chunk], 'original staging to output write')
            self.initializer = args[0]
            at = lambda offset: self.load(model.Pointer(args[0].region, args[0].offset + offset), 8)
            require((at(0), at(8), at(16)) == (model.Pointer('output'), self.length, self.progress), 'original progressive initializer')
            if self.failure and self.failure[:2] == ('write', self.iteration):
                self.events.append(('write-error', self.failure[2]))
                return self.failure[2]
        if name == self.names['finish']:
            self.armed()
            self.initializer = None
            self.events.append(('finish',))
            self.inside_finish = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.inside_finish = False
        if self.inside_finish and name in (self.names['deref'], self.names['take']):
            role = 'deref' if name == self.names['deref'] else 'take'
            if self.failure and self.failure[0] == role:
                self.events.append(('finish-fault', role, self.failure[2]))
                if self.failure[2] == 'unwind':
                    raise model.Unwind(self.exception)
                return (0, model.UNKNOWN)
        if name == self.names['predicate'] and self.failure == ('predicate', 0, 'unwind'):
            self.events.append(('predicate-unwind',))
            raise model.Unwind(self.exception)
        if name == 'llvm.usub.sat.i8':
            require(len(args) == 2 and all(type(value) is int and 0 <= value < 256 for value in args), 'bounded i8 saturating subtraction')
            return max(0, args[0] - args[1])
        return super().run(name, args, depth)


def scenarios(thorough):
    for length in (0, 1, 135, 136, 167, 168, 169, 337) if thorough else (0, 169, 337):
        for mode, valid in ((0, model.UNKNOWN), (0, 255), *((1, n) for n in range(10)), (1, 255)) if thorough else ((0, model.UNKNOWN), (1, 0), (1, 7)):
            yield length, mode, valid, None
            if length:
                for error in range(4):
                    yield length, mode, valid, ('clear', 0, error)
            if mode and (valid != 0 if not length else not 1 <= valid <= 8):
                continue
            for error in (*range(12), 'unwind'):
                yield length, mode, valid, ('preflight', 0, error)
            yield length, mode, valid, ('predicate', 0, 'unwind')
            if length:
                for role, error in (('take', None), ('take', 'unwind'), ('deref', 'unwind')):
                    yield length, mode, valid, (role, 0, error)
            for iteration in range(1, (length + 167) // 168 + 1):
                for error in (*range(12), 'unwind'):
                    yield length, mode, valid, ('read', iteration, error)
                for error in range(4):
                    yield length, mode, valid, ('write', iteration, error)
                for role in ('slice', 'as_mut', 'subtract'):
                    yield length, mode, valid, (role, iteration, None)
                yield length, mode, valid, ('copy', iteration, 'unwind')
                if mode and iteration == (length + 167) // 168:
                    yield length, mode, valid, ('last', iteration, None)
                    yield length, mode, valid, ('mask', iteration, 'unwind')


def expected(length, mode, valid, failure):
    cleanup = [('state', 859, 1, 1), ('state', 616, 8, 0)] + [
        ('wipe', 'storage', offset, width) for offset, width in ((656, 200), (624, 16), (640, 16), (856, 2), (864, 168), (1056, 2))]
    output_clear = [('wipe', 'output', 0, length)] if length else []
    stage_clear = [('wipe', 'storage', 864, 168)]
    result_error = lambda code: [('result', 8, 1, code), ('result', 0, 8, 2)]
    events, progress = [('begin',)], 0
    if failure and failure[0] == 'clear':
        return events + [('clear-error', failure[2])] + cleanup + result_error(10), 0, False
    events += output_clear + [('operation',)]
    error = 9 if mode and (valid != 0 if not length else not 1 <= valid <= 8) else None
    if error is None:
        events.append(('preflight',))
        if failure and failure[0] == 'preflight':
            error = failure[2]
    for iteration, offset in enumerate(range(0, length, 168), 1):
        if error is not None:
            break
        chunk = min(168, length - offset)
        if failure == ('slice', iteration, None):
            events.append(('missing', 'slice'))
            error = 9
            break
        events.append(('read', chunk))
        if failure and failure[:2] == ('read', iteration):
            error = failure[2]
            break
        if mode and offset + chunk == length:
            if failure == ('last', iteration, None):
                events.append(('missing', 'last'))
                error = 9
                break
            events.append(('mask', valid))
            if failure == ('mask', iteration, 'unwind'):
                error = 'unwind'
                break
        if failure == ('as_mut', iteration, None):
            events.append(('missing', 'as_mut'))
            error = 10
            break
        if failure and failure[:2] == ('write', iteration):
            events.append(('write-error', failure[2]))
            error = 10
            break
        events.append(('copy', chunk))
        if failure == ('copy', iteration, 'unwind'):
            error = 'unwind'
            break
        progress += chunk
        events += [('progress', progress)] + stage_clear
        if failure == ('subtract', iteration, None):
            events.append(('missing', 'subtract'))
            error = 8
            break
    if error is None:
        events.append(('finish',))
        if failure and failure[0] in ('deref', 'take'):
            events.append(('finish-fault', failure[0], failure[2]))
            error = 'unwind' if failure[2] == 'unwind' else 10
    if failure == ('predicate', 0, 'unwind'):
        return events + [('predicate-unwind',)] + output_clear + cleanup, progress, False
    if error == 'unwind':
        return events + output_clear + cleanup, progress, False
    if error is not None:
        return events + output_clear + result_error(error) + cleanup, progress, False
    fields = ((8, 8, model.Pointer('output')), (16, 8, length), (0, 8, 1)) if length else ((0, 8, 0),)
    return events + [('result', *field) for field in fields] + stage_clear, progress, True


def inspect(case, thorough=True):
    root, names, selected = closure(case)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in selected.items()}
    constants = '\n'.join(dict.fromkeys(line for text in (case.sha3, case.core, case.hash_core, case.kmac) for line in text.splitlines()
                                      if line.startswith(('@anon.', '@alloc_'))))
    count, visited = 0, set()
    for length, mode, valid, failure in scenarios(thorough):
        machine = OperationModel(functions, constants, names, length, mode, valid, failure)
        result = machine.allocate('result', 24)
        reader = machine.allocate('reader', 8)
        storage = machine.allocate('storage', 1088, payload=True)
        output = machine.allocate('output', length, payload=True)
        machine.fields(reader, [(0, 8, storage)])
        machine.events.clear()
        unwound = False
        try:
            require(machine.run(root, [result, reader, output, length, mode, valid]) is None, 'void composed producer')
        except model.Unwind as error:
            require(error.value == machine.exception, 'original exception propagated')
            unwound = True
        events, progress, success = expected(length, mode, valid, failure)
        require(machine.events == events, 'exact accelerated initialization/loop/completion/cleanup: '
                + repr((length, mode, valid, failure)) + '; actual=' + repr(machine.events) + '; expected=' + repr(events))
        require(unwound == (failure is not None and failure[2] == 'unwind') and machine.progress == progress,
                'exact unwind and initialized prefix')
        require(machine.load(reader, 8) == storage and not machine.in_guard and not machine.inside_operation
                and machine.guard_stores == ([] if failure and failure[0] == 'clear' else [0, 1] if success else [0]),
                'original storage and success-only guard completion')
        visited.update(machine.visited)
        count += 1
    for label, lines in model.blocks(selected[names['operation']]).items():
        if lines == ['unreachable'] or any('panicking' in line for line in lines):
            continue
        require((names['operation'], label) in visited, 'all selected nonpanic operation blocks exercised')
    return count, visited, selected


def main(record, shard):
    before = comparison.capture.sources()
    selected_cases = list(cases(record))
    require(len(selected_cases) == 8, 'eight accelerated debug paths')
    for case in selected_cases if shard is None else [selected_cases[shard]]:
        count, _, selected = inspect(case)
        print(f'Accelerated debug operation: {count} cases; {len(selected)} functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all 8 paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Preflight/read/copy/mask/volatile boundaries opaque; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    main(args.record.resolve(), args.shard)
