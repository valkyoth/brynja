#!/usr/bin/env python3
"""Mutate retained write/copy artifacts without recompiling or executing Rust."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_secret_output_write as check
from test_kmac_verify_comparisons import rejects, assembly_mutants


def mutants(function, compiler):
    copy = next(line for line in function.splitlines() if 'tail call fastcc void' in line)
    store = next(line for line in function.splitlines() if line.strip().startswith('store i64'))
    initialized = re.search('(' + check.SSA + r') = load i64, ptr %1, align 8', function)[1]
    symbol = re.search(check.comparison.SYMBOL, copy)
    args = check.comparison.arguments(copy, symbol.end())
    destination = check.comparison.pointer(args[0])
    gep = next(line for line in function.splitlines() if destination + ' = getelementptr' in line)
    overflow = next(line for line in function.splitlines() if ('extractvalue { i64, i1 }' if compiler == '1.90.0' else 'icmp ult') in line)
    bad_overflow = overflow.replace(', 1', ', 0') if compiler == '1.90.0' else overflow.replace('icmp ult', 'icmp ugt')
    for label, old, new in (
        ('inverted presence', 'icmp eq ptr', 'icmp ne ptr'),
        ('wrong progress field', 'ptr %self, i64 16', 'ptr %self, i64 8'),
        ('wrong capacity field', 'ptr %self, i64 8', 'ptr %self, i64 16'),
        ('broken overflow test', overflow, bad_overflow),
        ('reject exact capacity', 'icmp ugt i64', 'icmp uge i64'),
        ('omitted copy', copy, ''),
        ('duplicate copy', copy, copy + '\n' + copy),
        ('different copy callee', copy, copy.replace('10copy_bytes', '10unreviewed')),
        ('wrong source', copy, copy.replace('%input.0', destination)),
        ('wrong length', copy, copy.replace('%input.1', initialized)),
        ('wrong offset', gep, gep.replace('i64 ' + initialized, 'i64 %input.1')),
        ('premature commit', copy + '\n' + store, store + '\n' + copy),
        ('wrong committed progress', store, re.sub(r'store i64 ' + check.SSA, 'store i64 %input.1', store)),
        ('direct payload load', copy, '  %payload = load i8, ptr %input.0, align 1\n' + copy),
        ('wrong error discriminant', '[ 3, %start ]', '[ 0, %start ]'),
    ):
        yield label, function.replace(old, new)
    for branch in (line for line in function.splitlines() if line.strip().startswith('br i1')):
        edges = re.search(r'br i1 (' + check.SSA + r'), label %(\S+), label %([^,\s]+)', branch)
        yield 'reversed rejection branch', function.replace(branch, f'  br i1 {edges[1]}, label %{edges[3]}, label %{edges[2]}', 1)


def main(record):
    count, assembly_count = 0, 0
    for function, compiler, assembly, arm in check.cases(record):
        count += rejects(lambda body: check.inspect(body, compiler), function, mutants(function, compiler))
        assembly_count += rejects(lambda text: check.copy_boundary.inspect(text, arm), assembly,
                                  assembly_mutants(assembly, 'COPY', arm))
    if (count, assembly_count) != (144, 40):
        raise AssertionError(f'incomplete write/copy mutation campaign: {count}/{assembly_count}')
    print('Secret-output writes reject 144 guard/forwarding/commit LLVM regressions and 40 copy-boundary assembly regressions')
    print('Retained artifact-text mutations only; subprocess execution forbidden; no release-gate change')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
