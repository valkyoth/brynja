#!/usr/bin/env python3
"""Model retained debug output writes and descriptor helpers; no erasure proof."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_verify_comparisons as comparison
import check_secret_copy as copy_boundary
import debug_write_model as model

require = comparison.require


def closure(core):
    definitions = comparison.definitions(core)
    roots = [name for name, body in definitions.items()
             if 'SecretRegionInitialization5write' in name
             and model.parameters(body) == ['%self', '%input.0', '%input.1']]
    require(len(roots) == 1, 'unique debug write entry')
    header = definitions[roots[0]].splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    args = comparison.arguments(header, symbol.end())
    require(header.startswith('define i8 ') and comparison.pointer(args[0]) == '%self'
            and comparison.pointer(args[1]) == '%input.0' and args[2] == 'i64 %input.1',
            'borrowed debug write ABI')
    pending, selected = roots[:], {}
    while pending:
        name = pending.pop()
        if name in selected or name == 'llvm.uadd.with.overflow.i64':
            continue
        require(name in definitions, 'debug helper definition present: ' + name)
        selected[name] = definitions[name]
        for lines in model.blocks(definitions[name]).values():
            for line in lines:
                if 'call ' in line and ' asm ' not in line:
                    symbol = re.search(comparison.SYMBOL, line)
                    require(symbol is not None, 'direct debug helper call')
                    pending.append(symbol[1])
    require(len(selected) == 16, 'complete sixteen-function debug closure')
    copies = [name for name in selected if 'secret_memory_transfer10copy_bytes' in name]
    require(len(copies) == 1, 'one opaque borrowed-copy boundary')
    return roots[0], copies[0], selected


def scenarios():
    # These are metadata-model values, not manufactured Rust slices. Invalid
    # progress and huge lengths probe the rejection arithmetic without allocation.
    values = (0, 1, 7, 8, 63, 64, 65, 168, 169, 1024, (1 << 63) - 1)
    yield False, 0, 0, 0
    yield False, 0, 9, 7
    for capacity in values:
        for initialized in sorted({0, capacity // 2, capacity, capacity + 1, model.MASK}):
            for length in sorted({0, 1, 8, 65, capacity, max(0, capacity - initialized)}):
                yield True, capacity, initialized, length


def inspect(core, compiler):
    require(compiler in ('1.90.0', '1.98.1'), 'reviewed debug compiler')
    root, copy, selected = closure(core)
    functions = {name: (model.parameters(body), model.blocks(body))
                 for name, body in selected.items()}
    constants = '\n'.join(line for line in core.splitlines() if line.startswith('@anon.'))
    success = 4 if compiler == '1.90.0' else 255
    count = 0
    slice_helpers = [name for name in functions if '8and_then' in name]
    copy_helpers = [name for name in functions if 'secret_memory_transfer4copy' in name]
    require(len(slice_helpers) == len(copy_helpers) == 1, 'unique fault-injection boundaries')
    faults = [(slice_helpers[0], (0, model.UNKNOWN), 2)] + [(copy_helpers[0], error, error) for error in range(4)]
    inputs = [(case, None) for case in scenarios()] + [((True, 8, 2, 3), fault) for fault in faults]
    for (present, capacity, initialized, length), fault in inputs:
        machine = model.Model(functions, constants, copy, fault)
        owner = machine.allocate('owner', 24)
        output = machine.allocate('output', capacity, payload=True)
        source = machine.allocate('source', length, payload=True)
        machine.store(owner, 8, output if present else 0)
        machine.store(model.Pointer('owner', 8), 8, capacity)
        machine.store(model.Pointer('owner', 16), 8, initialized)
        machine.events.clear()
        result = machine.run(root, [owner, source, length])
        end = initialized + length
        expected = fault[2] if fault else 3 if not present else 1 if end > model.MASK else 2 if end > capacity else success
        require(result == expected, f'correct debug write result: {present}/{capacity}/{initialized}/{length}')
        events = [('fault', fault[0])] if fault else [] if expected != success else [
            ('copy', model.Pointer('output', initialized), source, length),
            ('store', 16, 8, end),
        ]
        require(machine.events == events, 'exact borrowed copy followed by sole progress commit')
        require(machine.load(owner, 8) == (output if present else 0)
                and machine.load(model.Pointer('owner', 8), 8) == capacity
                and machine.load(model.Pointer('owner', 16), 8) == (end if expected == success else initialized),
                'original output descriptor and failure progress preserved')
        count += 1
    return count


def cases(record):
    for row, _, core, assembly in comparison.cases(record):
        if row['profile'] == 'debug':
            yield core, row['compiler'].splitlines()[0].split()[1], assembly, row['target'].startswith('aarch64')


def main(record):
    before = comparison.capture.sources()
    builds = count = 0
    for core, compiler, assembly, arm in cases(record):
        count += inspect(core, compiler)
        copy_boundary.inspect(assembly, arm)
        builds += 1
    require(builds == 8 and before == comparison.capture.sources(), 'complete unchanged debug matrix')
    print(f'Debug output write: {builds} builds, sixteen-function closures, {count} modeled cases PASS')
    print('Actual Option/Result/slice/arithmetic helpers interpreted; five synthetic helper failures per build; opaque copy assembly checked separately')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Bounded metadata model, not full LLVM semantics, payload erasure, whole-call spills or native Arm/Windows qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
