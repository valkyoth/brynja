#!/usr/bin/env python3
"""Retained KMAC metadata cleanup assembly; not whole-call residue qualification."""
import argparse
import json
from pathlib import Path
import re

import check_debug_clear_assembly as assembly
import check_kmac_metadata_clear as llvm
import kmac_metadata_assembly_contracts as reviewed

require = llvm.require


def normalized(body, symbol, names):
    lines = assembly.normalized(body, symbol, names, 'UNUSED_LOCATION')
    # The shared normalizer already skips recognized non-% CFI directives.
    # These two retained x86 callee-save annotations are not machine work.
    return [line for line in lines if not re.fullmatch(r'\.cfi_offset %(?:rbx|r14), -\d+', line)]


def inspect(bodies, names, arm, profile, compiler):
    require(type(arm) is bool and profile in ('debug', 'release')
            and compiler in ('1.90.0', '1.98.1'), 'reviewed cleanup assembly configuration')
    expected = reviewed.contracts(arm, profile, compiler)
    require(set(bodies) == set(expected), 'complete cleanup assembly closure')
    require(len(set(names.values())) == len(names), 'distinct bound cleanup symbols')
    count = 0
    for role, contract in expected.items():
        lines = normalized(bodies[role], names[role], names)
        require(lines == contract, 'exact metadata cleanup assembly handoff: ' + role)
        count += sum(not line.endswith(':') for line in lines)
    return count


def cases(record):
    # Validates every artifact hash before accessing either package's assembly.
    for row, kmac, core, core_assembly in llvm.comparison.cases(record):
        functions, names = llvm.select(kmac, core)
        compiler = row['compiler'].splitlines()[0].split()[1]
        names_asm = {role: name.strip('"') for role, name in names.items()}
        kmac_paths = [record.parent / path for path in row['artifacts']
                      if Path(path).name.startswith('brynja_mac_kmac-') and path.endswith('.s')]
        require(len(kmac_paths) == 1, 'unique retained KMAC assembly artifact')
        kmac_assembly = kmac_paths[0].read_text()
        bodies = {role: assembly.select(core_assembly if role in ('CLEAR', 'EMPTY') else kmac_assembly,
                                       names_asm[role]) for role in functions}
        yield functions, names, bodies, names_asm, row['target'].startswith('aarch64-'), row['profile'], compiler


def main(record):
    before = llvm.comparison.capture.sources()
    builds = definitions = instructions = modeled = 0
    for functions, names, bodies, names_asm, arm, profile, compiler in cases(record):
        modeled += llvm.inspect(functions, names, compiler, profile)
        instructions += inspect(bodies, names_asm, arm, profile, compiler)
        definitions += len(bodies)
        builds += 1
    require(builds == 16 and definitions == 72 and before == llvm.comparison.capture.sources(),
            'complete unchanged KMAC cleanup assembly matrix')
    print(f'KMAC metadata assembly: {definitions} definitions, {instructions} machine instructions, {modeled} linked LLVM cases across {builds} builds PASS')
    print('Original 1/64/1-byte clearing arguments, bound tail calls, and empty/nonempty forwarding checked')
    print('Record SHA-256: ' + llvm.comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(llvm.comparison.recorded.inspector_sources(), sort_keys=True))
    print('Normal-return descriptor/ABI traffic only; not destructor reachability, unwind, prior-register erasure, whole-call residue or fresh native Arm/Windows evidence')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
