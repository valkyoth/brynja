#!/usr/bin/env python3
"""Retained alignment-one normal-return machine paths; not whole-call proof."""
import argparse
import json
from pathlib import Path
import re

import check_debug_byte_precondition as llvm
import byte_precondition_assembly_contracts as reviewed

comparison = llvm.comparison
require = llvm.require


def graph(body, role, names):
    lines = llvm.entry.normalized(body, names[role], names, '.Lalloc_0')
    blocks = {'entry': []}
    current = 'entry'
    for line in lines:
        # Exception metadata is not machine code; neither unwind nor panic
        # behavior is qualified by this normal-return check.
        if line in ('.cfi_remember_state', '.cfi_restore_state') or re.fullmatch(
                r'\.cfi_personality 15[56], DW\.ref\.rust_eh_personality|\.cfi_lsda (?:27|28), \.Lexception\d+', line):
            continue
        label = re.fullmatch(r'(B\d+):', line)
        if label:
            current = label[1]
            require(current not in blocks, 'unique byte-precondition assembly block')
            blocks[current] = []
        else:
            blocks[current].append(line)
    return blocks


def inspect(bodies, names, compiler, arm):
    expected = reviewed.contracts(compiler, arm)
    require(set(bodies) == set(names) == set(expected), 'complete machine precondition/callee inventory')
    operations = 0
    for role, (block_count, paths) in expected.items():
        actual = graph(bodies[role], role, names)
        require(set(actual) == {'entry', *(f'B{i}' for i in range(block_count))}, 'closed machine block inventory')
        for block, instructions in paths.items():
            require(actual[block] == instructions.splitlines(), 'exact alignment-one lowering: ' + role + '/' + block)
            operations += len(actual[block])
    return operations


def cases(record):
    for core, assembly, functions, names, compiler, arm in llvm.cases(record):
        bodies = {role: llvm.entry.select(assembly, name) for role, name in names.items()}
        yield core, assembly, functions, bodies, names, compiler, arm


def main(record):
    before = comparison.capture.sources()
    builds = functions_checked = operations = ir_operations = lengths = 0
    for core, assembly, functions, bodies, names, compiler, arm in cases(record):
        ir_operations += llvm.inspect(functions, names, compiler)
        operations += inspect(bodies, names, compiler, arm)
        functions_checked += len(bodies)
        caller_names = llvm.entry.identities(core)
        pair = {role: llvm.entry.select(assembly, caller_names[role]) for role in ('ENTRY', 'WRITE')}
        locations = set(re.findall(r'\.Lalloc_[0-9a-f]+', pair['ENTRY']))
        require(len(locations) == 1, 'unique caller source location')
        llvm.entry.inspect(pair, caller_names, locations.pop(), arm)
        lengths += llvm.entry.llvm.inspect(core)
        builds += 1
    require(builds == 8 and before == comparison.capture.sources(), 'complete unchanged machine precondition matrix')
    print(f'Byte-precondition assembly: {functions_checked} normal-return function contracts, {operations} machine instructions, {ir_operations} linked LLVM instructions across {builds} builds PASS')
    print(f'Caller alignment-one handoff rechecked; {lengths} existing LLVM length cases repeated; no payload loads in checked normal blocks')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Excludes invalid-alignment/panic/unwind bodies, pointer validity, all-input formal equivalence, native Arm/Windows and whole-call residue; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
