#!/usr/bin/env python3
"""Retained LLVM wrapper controls, without compiler/runtime execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_output_wrap as check
from test_kmac_verify_comparisons import rejects


def mutants(function):
    copy = next(line for line in function.splitlines() if '@llvm.memcpy.' in line)
    complete = next(line for line in function.splitlines() if 'call void @' in line and 'SecretRegionInitialization6finish' in line)
    branches = [line for line in function.splitlines() if line.strip().startswith('br i1')]
    pointer_store = next(line for line in function.splitlines() if line.strip().startswith('store ptr '))
    length_store = next(line for line in function.splitlines() if re.match(r'\s*store i64 %', line) and 'ptr %_0,' not in line)
    for label, old, new in (
        ('missing descriptor copy', copy, ''),
        ('short descriptor copy', copy, copy.replace('i64 24, i1 false', 'i64 16, i1 false')),
        ('oversized descriptor copy', copy, copy.replace('i64 24, i1 false', 'i64 32, i1 false')),
        ('wrong descriptor offset', 'ptr %initialization, i64 8', 'ptr %initialization, i64 16'),
        ('unreviewed copy primitive', copy, copy.replace('llvm.memcpy', 'llvm.memmove')),
        ('volatile copy', copy, copy.replace('i1 false', 'i1 true')),
        ('missing completion', complete, ''),
        ('duplicate completion', complete, complete + '\n' + complete),
        ('different completion callee', complete, complete.replace('6finish', '6unreviewed')),
        ('wrong completion source', complete, complete.replace(' %initialization1)', ' %initialization)')),
        ('wrong empty variant', 'store i64 0, ptr %_0', 'store i64 2, ptr %_0'),
        ('wrong error identity', 'store i8 4,', 'store i8 0,'),
        ('fabricated output pointer', pointer_store, re.sub(r'store ptr ' + check.SSA, 'store ptr null', pointer_store)),
        ('fabricated output length', length_store, re.sub(r'store i64 ' + check.SSA, 'store i64 0', length_store)),
        ('payload load', complete, '  %payload = load i64, ptr %unknown, align 8\n' + complete),
        ('early return', branches[0], '  ret void'),
        ('wrong result field', 'ptr %_0, i64 16', 'ptr %_0, i64 8'),
        ('unexpected scalar return', 'ret void', 'ret i64 0'),
    ):
        yield label, function.replace(old, new)
    for number, branch in enumerate(branches):
        match = re.search(r'br i1 (' + check.SSA + r'), label %(' + check.LABEL + r'), label %(' + check.LABEL + ')', branch)
        yield f'reversed branch {number}', function.replace(branch, f'  br i1 {match[1]}, label %{match[3]}, label %{match[2]}', 1)


def main(record):
    count, bindings = 0, 0
    for function, core in check.cases(record):
        count += rejects(lambda body: check.inspect(body, core), function, mutants(function))
        body = check.finish.select(core)
        cleanup = next(line for line in body.splitlines() if 'tail call' in line)
        altered = core.replace(body, body.replace(cleanup, ''), 1)
        bindings += rejects(lambda text: check.inspect(function, text), core, [('broken bound core handoff', altered)])
    if count != 160 or bindings != 8:
        raise AssertionError(f'incomplete wrapper mutation campaign: {count}/{bindings}')
    print('SHA-3 wrapping rejects 160 descriptor/call/result/branch mutations and eight broken core-handoff bindings')
    print('Retained LLVM-text mutations only; subprocess execution forbidden; no production or release-gate changes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
