#!/usr/bin/env python3
"""Inspect retained debug clear entry/write assembly, not whole-call erasure."""
import argparse
import json
from pathlib import Path
import re

import check_debug_volatile_clear as llvm

comparison = llvm.comparison
require = comparison.require

# Reviewed instruction contracts, not patterns learned from the input artifact.
# Entry passes zero to WRITE; WRITE preserves that byte over the pointer check.
# Iterator/fence/precondition machine bodies are not qualified by these pairs.
X86_ENTRY = '''subq $72, %rsp
movq %rdi, 32(%rsp)
movq %rsi, 40(%rsp)
callq *ITER@GOTPCREL(%rip)
movq %rax, 8(%rsp)
movq %rdx, 16(%rsp)
B0:
leaq 8(%rsp), %rdi
callq *NEXT@GOTPCREL(%rip)
movq %rax, 24(%rsp)
movq 24(%rsp), %rdx
movl $1, %eax
xorl %ecx, %ecx
cmpq $0, %rdx
cmoveq %rcx, %rax
testq $1, %rax
je B1
movq 24(%rsp), %rdi
movq %rdi, 48(%rsp)
movq %rdi, 64(%rsp)
movq %rdi, 56(%rsp)
xorl %esi, %esi
leaq LOCATION(%rip), %rdx
callq *WRITE@GOTPCREL(%rip)
jmp B0
B1:
movl $4, %edi
callq FENCE
addq $72, %rsp
retq'''
X86_WRITE = '''subq $40, %rsp
movq %rdx, (%rsp)
movq %rdi, 8(%rsp)
movb %sil, %al
movb %al, 23(%rsp)
movq %rdi, 24(%rsp)
movb %al, 39(%rsp)
movq (%rsp), %rdx
movq 8(%rsp), %rdi
movl $1, %esi
callq CHECK
movq 8(%rsp), %rax
movb 23(%rsp), %cl
movb %cl, (%rax)
addq $40, %rsp
retq'''
ARM_ENTRY = '''sub sp, sp, #80
stp x29, x30, [sp, #64]
add x29, sp, #64
mov x8, x0
str x8, [sp, #24]
str x1, [sp, #32]
bl ITER
str x0, [sp]
str x1, [sp, #8]
b B0
B0:
mov x0, sp
bl NEXT
str x0, [sp, #16]
ldr x8, [sp, #16]
subs x8, x8, #0
cset x8, ne
tbz w8, #0, B2
b B1
B1:
ldr x0, [sp, #16]
stur x0, [x29, #-24]
stur x0, [x29, #-8]
stur x0, [x29, #-16]
mov w1, wzr
adrp x2, LOCATION
add x2, x2, :lo12:LOCATION
bl WRITE
b B0
B2:
mov w0, #4
bl FENCE
ldp x29, x30, [sp, #64]
add sp, sp, #80
ret'''
ARM_WRITE = '''sub sp, sp, #64
stp x29, x30, [sp, #48]
add x29, sp, #48
str x0, [sp, #8]
str w1, [sp, #20]
str x2, [sp, #24]
stur x0, [x29, #-16]
sturb w1, [x29, #-1]
b B0
B0:
ldr x2, [sp, #24]
ldr x0, [sp, #8]
mov w8, #1
mov w1, w8
bl CHECK
b B1
B1:
ldr w8, [sp, #20]
ldr x9, [sp, #8]
strb w8, [x9]
ldp x29, x30, [sp, #48]
add sp, sp, #64
ret'''


def identities(core):
    root, precondition, selected = llvm.closure(core)
    result = {'ENTRY': root, 'CHECK': precondition}
    for role, token in (('ITER', '9into_iter'), ('NEXT', '4next'),
                        ('WRITE', '14write_volatile'), ('FENCE', '14compiler_fence')):
        matches = [name for name in selected if token in name and name != precondition]
        require(len(matches) == 1, 'unique bound debug assembly helper: ' + role)
        result[role] = matches[0]
    require(len(set(result.values())) == 6, 'distinct debug assembly identities')
    return {role: name.strip('"') for role, name in result.items()}


def select(assembly, symbol):
    starts = list(re.finditer(r'^' + re.escape(symbol) + r':$', assembly, re.M))
    require(len(starts) == 1, 'unique exact debug assembly symbol')
    tail = assembly[starts[0].end():]
    end = re.search(r'^\.Lfunc_end\d+:$', tail, re.M)
    require(end is not None, 'explicit debug assembly function end')
    return assembly[starts[0].start():starts[0].end() + end.end()]


def normalized(body, symbol, names, location):
    lines = body.splitlines()
    require(lines[0] == symbol + ':' and re.fullmatch(r'\.Lfunc_end\d+:', lines[-1]),
            'debug assembly function boundaries')
    instructions = []
    for raw in lines[1:-1]:
        line = re.sub(r'\s+', ' ', raw.strip())
        if not line or re.fullmatch(r'\.L(?:func_begin|tmp)\d+:', line):
            continue
        if re.fullmatch(r'\.file \d+ "[^";\n]+" "[^";\n]+"', line) or re.fullmatch(
                r'\.loc \d+ \d+ \d+(?: (?:is_stmt [01]|prologue_end|epilogue_begin))*', line) or re.fullmatch(
                r'\.cfi_(?:startproc|endproc|def_cfa_offset \d+|def_cfa \w+, \d+|'
                r'offset \w+, -?\d+|restore \w+)', line):
            continue  # Debug/unwind directives, not machine instructions.
        instructions.append(line)
    labels = [line[:-1] for line in instructions if re.fullmatch(r'\.LBB\d+_\d+:', line)]
    require(len(labels) == len(set(labels)), 'unique debug assembly blocks')
    replacements = {name: role for role, name in names.items()}
    replacements.update({label: 'B' + str(index) for index, label in enumerate(labels)})
    replacements[location] = 'LOCATION'
    # Match complete identifiers: an unreviewed callee with a known-name prefix
    # must not inherit the known helper's role.
    pattern = r'(?<![\w.$])(?:' + '|'.join(re.escape(x) for x in replacements) + r')(?![\w.$])'
    return [re.sub(pattern, lambda match: replacements[match[0]], line) for line in instructions]


def inspect(bodies, names, location, arm):
    require(re.fullmatch(r'\.Lalloc_[0-9a-f]+', location), 'public source-location constant')
    count = 0
    expected = {'ENTRY': ARM_ENTRY if arm else X86_ENTRY, 'WRITE': ARM_WRITE if arm else X86_WRITE}
    require(set(bodies) == set(expected), 'complete debug assembly pair')
    for role, contract in expected.items():
        lines = normalized(bodies[role], names[role], names, location)
        require(lines == contract.splitlines(), 'exact debug zero-forwarding/write lowering: ' + role)
        count += len(lines)
    return count


def cases(record):
    for core, _, assembly, arm in llvm.writing.cases(record):
        names = identities(core)
        bodies = {role: select(assembly, names[role]) for role in ('ENTRY', 'WRITE')}
        locations = set(re.findall(r'\.Lalloc_[0-9a-f]+', bodies['ENTRY']))
        require(len(locations) == 1, 'single public source location')
        location = locations.pop()
        require(len(re.findall(r'^' + re.escape(location) + ':$', assembly, re.M)) == 1,
                'source-location constant defined in retained assembly')
        yield core, bodies, names, location, arm


def main(record):
    before = comparison.capture.sources()
    builds = modeled = instructions = 0
    for core, bodies, names, location, arm in cases(record):
        modeled += llvm.inspect(core)
        instructions += inspect(bodies, names, location, arm)
        builds += 1
    require(builds == 8 and before == comparison.capture.sources(), 'complete unchanged debug matrix')
    print(f'Debug clear assembly: {builds} entry/write pairs; {instructions} normalized instructions/labels; {modeled} linked LLVM cases PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Iterator/fence/precondition machine bodies, whole-call residue and native Arm/Windows remain outside this check; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
