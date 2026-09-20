#!/usr/bin/env python3
"""Mutate retained reader admission/counter encoding without invoking compilers."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_read_counter as check
from test_kmac_verify_comparisons import rejects


def mutants(function, compiler):
    lines = function.splitlines()
    session = next(line for line in lines if 'invoke ' in line and '13KeccakSession5check' in line)
    store = next(line for line in lines if 'store <16 x i8>' in line)
    for label, old, new in (
        ('wrong terminal metadata', 'ptr %self, i64 859', 'ptr %self, i64 858'),
        ('wrong squeezing metadata', 'ptr %self, i64 858', 'ptr %self, i64 859'),
        ('wrong output counter', 'ptr %self, i64 640', 'ptr %self, i64 641'),
        ('wrong session owner', session, session.replace('%self', '%wrong_owner')),
        ('missing session check', session, ''),
        ('missing counter commit', store, ''),
        ('duplicate counter commit', store, store + '\n' + store),
        ('wrong counter width', store, store.replace('<16 x i8>', '<8 x i8>')),
    ):
        yield label, function.replace(old, new, 1)
    for line in lines:
        if re.search(r'getelementptr .*ptr %self, i64 65[0-5]$', line.strip()):
            yield 'wrong upper counter byte', function.replace(line, re.sub(r'65[0-5]$', '640', line), 1)
        if re.search(r' = shl .*i128 .*?, (?:64|72|80|88|96|104|112|120)$', line.strip()):
            yield 'wrong reconstructed byte significance', function.replace(line, re.sub(r', \d+$', ', 0', line), 1)
        if ' = lshr <' in line:
            yield 'corrupted output byte shifts', function.replace(line, line.replace('i128 8', 'i128 7'), 1) if 'i128 8' in line else function.replace(line, line.replace('i128 16', 'i128 15').replace('i128 32', 'i128 31').replace('i128 64', 'i128 63'), 1)
    # Admission branches precede the first loop entry; do not relabel loop tests as preflight coverage.
    for label, body in check.read.shared.graph(function).items():
        if not any(token in '\n'.join(body) for token in ('select i1', '13KeccakSession5check', '@llvm.uadd.with.overflow.i128(', 'icmp ult i128')):
            continue
        branch = body[-1]
        found = re.fullmatch('br i1 (' + check.SSA + '), label %(' + check.read.LABEL + '), label %(' + check.read.LABEL + ')', branch)
        if found:
            yield 'reversed admission branch', function.replace(branch, f'br i1 {found[1]}, label %{found[3]}, label %{found[2]}', 1)
    addition = next(line for line in lines if re.search(r' = add(?: nuw)? i128 ', line))
    yield 'wrong admitted sum', function.replace(addition, addition.replace(' = add', ' = xor'), 1)
    if compiler == '1.98.1':
        high_byte = next(line for line in lines if re.search(r' = shl nuw i128 .*?, 120$', line.strip()))
        yield 'high counter bit made poison', function.replace(high_byte, high_byte.replace('shl nuw', 'shl nuw nsw'), 1)
    else:
        overflow = next(line for line in lines if 'extractvalue { i128, i1 }' in line)
        yield 'wrong overflow tuple field', function.replace(overflow, overflow.replace(', 1', ', 0'), 1)


def main(record):
    counts = []
    for sha3, core, cpu, compiler in check.read.cases(record):
        definitions = check.read.comparison.definitions(sha3)
        function = definitions[check.read.shared.unique(definitions, 'accelerated', '6Engine4read')]
        if compiler == '1.98.1':
            # An earlier overflow check already makes this later sum nonwrapping.
            # Adding nuw here is a valid strengthening, not a regression.
            addition = next(line for line in function.splitlines() if ' = add i128 ' in line)
            strengthened = function.replace(addition, addition.replace('add i128', 'add nuw i128'), 1)
            check.inspect(sha3.replace(function, strengthened, 1), core, cpu, compiler, thorough=False)
        counts.append(rejects(lambda body: check.inspect(sha3.replace(function, body, 1), core, cpu, compiler, thorough=False),
                              function, mutants(function, compiler)))
    if counts != [29] * 4:
        raise AssertionError(f'incomplete counter mutation matrix: {counts}')
    print('Accelerated read counters reject 116 retained-LLVM admission/metadata/encoding regressions; two valid arithmetic-strengthening controls pass')
    print('Subprocess execution forbidden; no compiled fault campaign or release-gate change')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
