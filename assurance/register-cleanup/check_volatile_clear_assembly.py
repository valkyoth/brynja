#!/usr/bin/env python3
"""Bind retained optimized clear assembly to inspected LLVM; not whole-call proof."""
import argparse
import json
from pathlib import Path
import re

import check_volatile_clear as llvm

comparison = llvm.comparison
require = comparison.require

# Closed, manually reviewed lowering contracts. Public pointer/length arithmetic
# and literal-zero stores only; no payload loads, calls, stack or vector work.
X86 = [
    'testq %rsi, %rsi', 'je END',
    'movq %rsi, %rcx', 'movq %rdi, %rax', 'andq $7, %rcx', 'je BULK_CHECK',
    'movq %rdi, %rax', 'REMAINDER:',
    'movb $0, (%rax)', 'incq %rax', 'decq %rcx', 'jne REMAINDER',
    'BULK_CHECK:', 'cmpq $8, %rsi', 'jb END', 'addq %rsi, %rdi', 'BULK:',
    *[f'movb $0, {str(offset) if offset else ""}(%rax)' for offset in range(8)],
    'addq $8, %rax', 'cmpq %rdi, %rax', 'jne BULK', 'END:', 'BARRIER', 'retq',
]
ARM = ['cbz x1, END', 'LOOP:', 'subs x1, x1, #1',
       'strb wzr, [x0], #1', 'b.ne LOOP', 'END:', 'BARRIER', 'ret']


def select(assembly):
    symbols = list(re.finditer(r'(?m)^(_\S*secret_memory_volatile23zeroize_region_volatile[^\s:]*):[^\n]*$', assembly))
    require(len(symbols) == 1, 'unique clearing assembly function')
    start = symbols[0]
    tail = assembly[start.end():]
    end = re.search(r'(?m)^\.Lfunc_end\d+:', tail)
    require(end is not None, 'explicit clearing assembly end')
    return assembly[start.start():start.end() + end.end()]


def inspect(body, arm):
    lines = body.splitlines()
    require(re.fullmatch(r'_\S*secret_memory_volatile23zeroize_region_volatile[^\s:]*:', lines[0]) is not None,
            'clearing symbol boundary')
    require(re.fullmatch(r'\.Lfunc_end\d+:', lines[-1]) is not None, 'clearing end boundary')
    instructions = []
    labels = []
    for raw in lines[1:-1]:
        line = re.sub(r'\s+', ' ', raw.strip())
        if not line or line in ('.cfi_startproc', '.p2align 4'):
            continue
        if line == ('//MEMBARRIER' if arm else '#MEMBARRIER'):
            instructions.append('BARRIER')
            continue
        if re.fullmatch(r'\.LBB\d+_\d+:', line):
            labels.append(line[:-1])
        instructions.append(line)
    roles = ['LOOP', 'END'] if arm else ['REMAINDER', 'BULK_CHECK', 'BULK', 'END']
    require(len(labels) == len(roles) and len(set(labels)) == len(labels), 'closed unique clearing labels')
    names = dict(zip(labels, roles))
    normalized = [re.sub(r'\.LBB\d+_\d+', lambda match: names.get(match[0], 'UNKNOWN_LABEL'), line)
                  for line in instructions]
    require(normalized == (ARM if arm else X86), 'exact reviewed zero-store and loop lowering')
    # BARRIER is a compiler annotation, not a hardware fence instruction. The
    # LLVM checker separately requires the actual singlethread SeqCst fence.
    return len(instructions)


def cases(record):
    for row, _, core, assembly in comparison.cases(record):
        if row['profile'] == 'release':
            yield llvm.select(core), select(assembly), row['target'].startswith('aarch64')


def main(record):
    before = comparison.capture.sources()
    builds = modeled = instructions = 0
    for function, body, arm in cases(record):
        modeled += llvm.inspect(function)
        instructions += inspect(body, arm)
        builds += 1
    require(builds == 8 and before == comparison.capture.sources(), 'complete unchanged clearing assembly matrix')
    print(f'Volatile clear assembly: {builds} exact lowering contracts and {modeled} linked LLVM length cases PASS')
    print(f'{instructions} normalized instructions/labels/annotations; literal-zero stores, no payload loads/calls/stack/vector work')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not debug assembly, binary execution proof, arbitrary compiler output, whole-call spills or native Arm/Windows qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
