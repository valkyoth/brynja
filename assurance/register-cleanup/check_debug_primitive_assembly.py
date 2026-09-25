#!/usr/bin/env python3
"""Recheck exact retained copy/mask leaves; no rebuild or whole-caller claim."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_reader_primitives as check
import check_secret_copy as copy
import check_secret_mask as mask
import debug_primitive_contracts as contracts
from check_debug_clear_assembly import select


def operand_mutants(body, arm, role):
    replacements = ({
        'ldr x4,[x1,x5]': 'ldr x4,[x0,x5]', 'str x4,[x0,x5]': 'str x4,[x1,x5]',
        'add x5,x5,#8': 'add x5,x5,#7', 'sub x6,x6,#8': 'sub x6,x6,#7',
        'mov x6,x2': 'mov x6,x1', 'mov x4,xzr': 'mov x5,xzr',
    } if arm else {
        'movq (%rsi,%rcx),%rax': 'movq (%rdi,%rcx),%rax', 'movq %rax,(%rdi,%rcx)': 'movq %rax,(%rsi,%rcx)',
        'addq $8,%rcx': 'addq $7,%rcx', 'subq $8,%rdx': 'subq $7,%rdx',
        'movq %rdx,%r8': 'movq %rsi,%r8', 'xorl %eax,%eax': 'xorl %ecx,%ecx',
    }) if role == 'COPY' else ({
        'and w4,w4,w9': 'and w4,w4,w10', 'orr w4,w4,w10': 'orr w4,w4,w9',
        'strb w4,[x8]': 'str w4,[x8]', 'ldr w9,[sp,#28]': 'ldr w9,[sp,#12]', 'mov x4,xzr': 'mov x5,xzr',
    } if arm else {
        'andb %cl,%al': 'andb %dl,%al', 'orb %dl,%al': 'orb %cl,%al',
        'movb %al,(%rdi)': 'movl %eax,(%rdi)', 'movb %sil,%cl': 'movb %dl,%cl', 'xorl %eax,%eax': 'xorl %ecx,%ecx',
    })
    seen = set()
    for line in body.splitlines():
        operation = re.sub(r'\s+', ' ', line.strip()).replace(', ', ',')
        if operation in replacements:
            assert operation not in seen
            seen.add(operation)
            yield body.replace(line, replacements[operation])
    assert seen == set(replacements)


def inspect(case, assembly, arm):
    names, _, _ = check.setup(case)
    for role, checker in (('raw_copy', copy), ('raw_mask', mask)):
        body = select(assembly, names[role].strip('"'))
        checker.inspect(body, arm)
        contracts.inspect(body, arm, 'COPY' if role == 'raw_copy' else 'MASK')
    return names


def main(record):
    before = check.comparison.capture.sources()
    cases = list(check.composed.operation.cases(record))
    rows = [(row, core, assembly) for row, _, core, assembly in check.comparison.cases(record)
            if row['profile'] == 'debug' and row['mode'] == 'accelerated']
    assert len(rows) == 4
    rejects = controls = paths = 0
    for row, core, assembly in rows:
        matching = [case for case in cases if case.core == core and case.compiler in row['compiler']]
        assert len(matching) == 2
        arm = row['target'].startswith('aarch64')
        names = inspect(matching[0], assembly, arm)
        assert inspect(matching[1], assembly, arm) == names
        paths += 2
        for role, checker, label in (('raw_copy', copy, 'COPY'), ('raw_mask', mask, 'MASK')):
            body = select(assembly, names[role].strip('"'))
            for marker in ('BEGIN', 'ERASE', 'END'):
                operations = ('str x4, [sp]', 'ldr x4, [x0]', 'ret') if arm else ('pushq %rax', 'movq (%rdi), %rax', 'retq')
                for instruction in operations:
                    mutant, n = re.subn(r'(?m)^(.*BRYNJA_' + label + '_' + marker + r'.*)$',
                                        lambda m: instruction + '\n' + m[1], body)
                    assert n == 1 and mutant != body
                    try:
                        checker.inspect(mutant, arm)
                        contracts.inspect(mutant, arm, label)
                    except ValueError:
                        rejects += 1
                    else:
                        raise AssertionError('accepted primitive spill/reload/return mutation')
            for mutant in operand_mutants(body, arm, label):
                try:
                    contracts.inspect(mutant, arm, label)
                except ValueError:
                    rejects += 1
                else:
                    raise AssertionError('accepted primitive ABI/address/width/cleanup mutation')
            renamed = re.sub(r'\.Ltmp(\d+)', lambda m: '.Ltmp' + str(int(m[1]) + 1000000), body)
            assert renamed != body
            checker.inspect(renamed, arm)
            contracts.inspect(renamed, arm, label)
            controls += 1
        print(f'Retained primitive assembly: {row["target"]}; {matching[0].compiler}; both strengths PASS', flush=True)
    assert (paths, rejects, controls) == (8, 116, 8)
    assert before == check.comparison.capture.sources()
    print('Four same-row assembly pairs bind eight caller paths; 116 mutants rejected; eight label controls PASS')
    print('Only exact raw leaf normal-return instruction contracts; wrappers/whole-caller spills and interruption remain separate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
