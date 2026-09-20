#!/usr/bin/env python3
"""Negative controls for actual-crate Keccak inspection, without recompilation."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_recorded_keccak as check


def rejects(text, mutant, arm, batch):
    if mutant == text:
        raise AssertionError('mutation did not change assembly')
    try:
        check.inspect(mutant, arm, batch)
    except ValueError:
        return
    raise AssertionError('kernel or public-table mutation accepted')


def main(record):
    boundaries = tables = 0
    original = check.x86.REGISTERS, check.x86.SHA256, check.aarch64.GP, check.aarch64.VECTOR, check.aarch64.SHA256
    for text, arm, batch in check.cases(record):
        check.inspect(text, arm, batch)
        load = 'ldr x4, [x0]' if arm else 'movq (%rdi), %rax'
        spill = 'str x4, [sp]' if arm else 'pushq %rax'
        for mutant in (
            text.replace('BRYNJA_SECRET_BEGIN', 'MISSING_BEGIN'),
            text.replace('BRYNJA_SECRET_END', 'MISSING_END'),
            text.replace('BRYNJA_REGISTER_ERASE', 'MISSING_ERASE'),
            re.sub(r'(?m)^(.*BRYNJA_REGISTER_ERASE[^\n]*\n)[^\n]+\n', r'\1', text),
            re.sub(r'(?m)^(.*BRYNJA_SECRET_BEGIN.*)$', load + r'\n\1', text),
            re.sub(r'(?m)^(.*BRYNJA_SECRET_END.*)$', load + r'\n\1', text),
            re.sub(r'(?m)^(.*BRYNJA_SECRET_END.*)$', r'\1\n' + load, text),
            re.sub(r'(?m)^(.*BRYNJA_SECRET_BEGIN.*)$', r'\1\n' + spill, text),
        ):
            rejects(text, mutant, arm, batch)
            boundaries += 1

        # Optimized rows fold the table address into each kernel; debug rows
        # keep the input pointer. Mutate the same prologue/table actually used.
        register = 'rsi' if batch else 'r9'
        address = (r'(?m)^\s*adrp\s+x8, (\.Lalloc_[a-f0-9]+)\n'
                   r'\s*add\s+x8, x8, :lo12:\1\n') if arm else (
                       r'(?m)^\s*leaq\s+(\.Lalloc_[a-f0-9]+)\(%rip\), %' + register + r'\n')
        found = re.search(address, check.kernel_body(text, arm, batch).split('BRYNJA_SECRET_BEGIN')[0])
        if not found:
            continue
        label = found[1]
        table = re.search(re.escape(label) + r':\n\s*\.ascii\s+"([^\n]*)"', text)
        if table is None:
            raise AssertionError('expected actual folded public table')
        for index, mutant in enumerate((
            text.replace('.rodata.' + label + ',"a"', '.data.' + label + ',"aw"'),
            text[:table.start(1)] + 'X' + text[table.start(1):],
            text.replace('.size\t' + label + ', 192', '.size\t' + label + ', 191'),
            text + '\n' + label + ':\n',
            text.replace(found[0], found[0].replace('adrp', 'ldr') if arm else found[0].replace('leaq', 'movq')),
            text.replace(found[0], found[0].replace('x8', 'x7') if arm else found[0].replace('%' + register, '%rax')),
            text.replace(found[0], found[0] + found[0]),
        )):
            try:
                rejects(text, mutant, arm, batch)
            except AssertionError as error:
                raise AssertionError(f'table mutant {index}; arm={arm}, batch={batch}') from error
            tables += 1
    if boundaries != 128 or tables != 56:
        raise AssertionError(f'incomplete mutation coverage: {boundaries}, {tables}')
    if original != (check.x86.REGISTERS, check.x86.SHA256, check.aarch64.GP, check.aarch64.VECTOR, check.aarch64.SHA256):
        raise AssertionError('shared validator configuration was not restored')
    print(f'Actual Keccak boundaries reject {boundaries} erasure/load/spill and {tables} constant-address/table mutants')
    print('Inspector configuration restored; subprocess execution forbidden; assembly-text mutants only')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('inspection must not start a build or runtime')):
        main(parser.parse_args().record)
