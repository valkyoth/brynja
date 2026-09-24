#!/usr/bin/env python3
"""Regressions for retained accelerated producer progress and final-byte masking."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_accelerated_output_loop as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, names, labels):
    graph = check.staging.graph(function)
    for label in labels:
        lines = graph[label]
        for index, line in enumerate(lines):
            yield 'missing loop operation', replace_block(function, label, lines[:index] + lines[index + 1:])
            changes = []
            if 'getelementptr' in line:
                changes.append(('wrong staging/metadata address', re.sub(r', ptr ' + check.SSA + ',', ', ptr %foreign,', line)))
                if re.search(r'i64 -?\d+$', line):
                    changes.append(('wrong final-byte offset', re.sub(r'i64 (-?\d+)$', lambda m: 'i64 ' + str(int(m[1]) + 1), line)))
            if ' load ' in line:
                changes.append(('foreign loop/owner metadata', re.sub(r', ptr ' + check.SSA + ',', ', ptr %foreign,', line)))
            if 'phi ' in line:
                changes.append(('wrong initial remaining count', re.sub(r'\[ [^,]+,', '[ 0,', line, count=1)))
                changes.append(('lost loop progress', re.sub(r'\], \[ [^,]+,', '], [ 0,', line, count=1)))
            if 'sub nuw i64' in line:
                changes.append(('wrong progress direction', line.replace('sub nuw i64', 'add nuw i64')))
                changes.append(('zero progress', re.sub(check.SSA + '$', '0', line)))
            if 'icmp ' in line:
                changes.append(('inverted admission/loop predicate', re.sub(r'icmp (eq|ne|ult|ugt)', lambda m: 'icmp ' + {'eq': 'ne', 'ne': 'eq', 'ult': 'ugt', 'ugt': 'ult'}[m[1]], line)))
            if ' = add i8 ' in line:
                changes.append(('wrong valid-bit range', line.replace(', -1', ', -2')))
            if ' = shl ' in line and ' i128 ' in line:
                changes.append(('wrong counter significance', re.sub(r', \d+$', ', 0', line)))
            if ' = xor i128 ' in line:
                changes.append(('wrong overflow complement', line.replace(', -1', ', 0')))
            if ' = select i1 ' in line:
                changes.append(('ignored terminal state', line.replace('i1 true', 'i1 false')))
            if ' call ' in ' ' + line or ' invoke ' in ' ' + line:
                name, args = check.adapter.routes.guard.call(line)
                if not name.startswith('llvm.'):
                    changes.append(('unbound loop dependency', line.replace(name, 'foreign_callee')))
                    for arg in args:
                        if arg.startswith('ptr ') and 'sret(' not in arg:
                            changes.append(('foreign read/write/mask storage', line.replace(arg, arg.replace(check.comparison.pointer(arg), '%foreign'), 1)))
                    if name in (names['read'], names['write']):
                        changes.append(('empty read/write chunk', line.replace(args[2], 'i64 noundef 0')))
                    if name == names['clear']:
                        changes.append(('partial staging clear', line.replace(args[1], 'i64 noundef 167')))
                    if name == names['mask']:
                        changes.append(('sets secret-output bits', line.replace(args[2], 'i8 noundef 1')))
                elif name == 'llvm.umin.i64':
                    changes.append(('oversized chunk', line.replace('i64 168)', 'i64 169)')))
                    changes.append(('unbounded chunk', line.replace('llvm.umin', 'llvm.umax')))
                elif name == 'llvm.usub.sat.i8':
                    changes.append(('wrong final-bit width', line.replace('i8 8,', 'i8 7,')))
            if ' = and i8 ' in line:
                changes.append(('wrong mask shift', line.replace(', 7', ', 6')))
            if ' = lshr i8 ' in line:
                changes.append(('wrong bit order', line.replace('lshr', 'shl')))
            for reason, changed in changes:
                assert changed != line, (reason, line)
                yield reason, replace_block(function, label, lines[:index] + [changed] + lines[index + 1:])
        if lines[-1].startswith('br i1 '):
            branch = re.fullmatch(r'(br i1 .+), label %(.+), label %(.+)', lines[-1])
            yield 'reversed iteration decision', replace_block(function, label, lines[:-1] + [f'{branch[1]}, label %{branch[3]}, label %{branch[2]}'])
    for label in labels[1:]:
        yield 'bypassed loop stage', function[:-1] + 'bypass:\n  br label %' + label + '\n}'


def dependencies(case):
    reader = case.reader
    definitions = check.comparison.definitions(reader.core)
    writer = definitions[check.staging.unique(definitions, 'Initialization5write')]
    mask = definitions[check.staging.unique(definitions, '22apply_secret_byte_mask')]
    drop = definitions[check.staging.unique(definitions, 'SecretRegionInitialization', '4drop')]
    engine = check.comparison.definitions(reader.sha3)
    read = engine[check.staging.unique(engine, 'accelerated', '6Engine4read')]
    yield 'missing owned writer', replace(case, reader=replace(reader, core=reader.core.replace(writer, '')))
    yield 'missing mask wrapper', replace(case, reader=replace(reader, core=reader.core.replace(mask, '')))
    yield 'missing actual destination destructor', replace(case, reader=replace(reader, core=reader.core.replace(drop, '')))
    yield 'forged keep mask', replace(case, reader=replace(reader, core=reader.core.replace(mask, mask.replace('%keep)', '0)').replace('%keep,', '0,'))))
    yield 'missing engine read', replace(case, reader=replace(reader, sha3=reader.sha3.replace(read, '')))
    yield 'truncated engine cursor increment', replace(case, reader=replace(reader, sha3=reader.sha3.replace(read, read.replace('i64 616', 'i64 617'))))
    cpu = check.comparison.definitions(case.cpu)
    session = cpu[check.staging.unique(cpu, '13KeccakSession5check')]
    yield 'missing actual session check', replace(case, cpu=case.cpu.replace(session, ''))
    yield 'nonvolatile clearing', replace(case, reader=replace(reader, core=reader.core.replace('store volatile i8 0,', 'store i8 0,')))
    yield 'wrong assembly architecture', replace(case, reader=replace(reader, arm=not reader.arm))


def main(record):
    before = check.comparison.capture.sources()
    counts, bindings, controls = [], 0, 0
    for case in check.cases(record):
        function, names, compiler, _ = check.bind(case, False)
        inspect = lambda value: check.inspect(value, names, compiler)
        labels = inspect(function)
        counts.append(rejects(inspect, function, mutations(function, names, labels)))
        for changed in (function.replace('start:\n', 'start:\n; harmless producer loop comment\n', 1),
                        re.sub(r'%\d+(?![\w.])', lambda m: '%loop' + m[0][1:] if m[0] not in ('%0', '%1') else m[0], function)):
            assert changed != function
            inspect(changed)
            controls += 1
        if compiler == '1.90.0':
            changed = function.replace('= call { i128, i1 } @llvm.uadd', '= tail call { i128, i1 } @llvm.uadd')
            assert changed != function
            inspect(changed)
            controls += 1
        def bound(value):
            function, names, compiler, _ = check.bind(value, False)
            return check.inspect(function, names, compiler)
        bindings += rejects(bound, case, dependencies(case))
    assert counts == [242] * 4 + [239] * 4 and bindings == 72 and controls == 20, (counts, bindings, controls)
    assert before == check.comparison.capture.sources()
    print(f'Accelerated output loop rejects {sum(counts)} LLVM and {bindings} dependency regressions; {controls} controls PASS; per-path={counts}')
    print('Saved artifacts only; subprocess execution forbidden; no production or release-gate change')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
