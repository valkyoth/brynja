#!/usr/bin/env python3
"""Mutate actual retained entry ordering, ownership transfer and cleanup."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_accelerated_initialization as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutants(function, labels):
    graph = check.readers.staging.graph(function)
    for label in labels:
        lines = graph[label]
        for index, line in enumerate(lines):
            yield 'removed entry operation', replace_block(function, label, lines[:index] + lines[index + 1:])
            changes = []
            if 'getelementptr' in line:
                changes.append(('wrong descriptor/storage field', re.sub(r'i64 (\d+)$', lambda m: 'i64 ' + str(int(m[1]) + 1), line)))
            if line.startswith('store '):
                changes.append(('redirected metadata store', re.sub(r', ptr ' + check.SSA + ',', ', ptr %foreign,', line)))
            if ' load ' in line:
                changes.append(('foreign metadata read', re.sub(r', ptr ' + check.SSA + ',', ', ptr %foreign,', line)))
            if 'phi ' in line:
                changes.append(('wrong predecessor value', re.sub(r'\[ [^,]+,', '[ undef,', line, count=1)))
            if 'icmp eq i64 %output.1, 0' in line:
                changes.append(('nonempty bypasses clearing', line.replace('icmp eq', 'icmp ne')))
            if ' call ' in ' ' + line:
                name, args = check.adapter.routes.guard.call(line)
                if name == 'llvm.memcpy.p0.p0.i64':
                    for old, new in (('i64 23,', 'i64 22,'), ('i64 23,', 'i64 24,'), (args[0], args[1]), (args[1], args[0])):
                        changes.append(('truncated/oversized/reversed descriptor copy', line.replace(old, new, 1)))
                elif not name.startswith('llvm.'):
                    changes.append(('unbound dependency', line.replace(name, 'foreign_callee')))
                    if 'Initialization5begin' in name:
                        changes.extend((('substituted destination', line.replace('%output.0', '%foreign')),
                                        ('truncated destination', line.replace(args[2], 'i64 noundef 0'))))
            for reason, changed in changes:
                assert changed != line, reason
                yield reason, replace_block(function, label, lines[:index] + [changed] + lines[index + 1:])
        if lines[-1].startswith('br i1 '):
            branch = re.fullmatch(r'(br i1 .+), label %(.+), label %(.+)', lines[-1])
            yield 'reversed lifecycle edge', replace_block(function, label, lines[:-1] + [f'{branch[1]}, label %{branch[3]}, label %{branch[2]}'])
    yield 'state read before destination clearing', function.replace('start:\n', 'start:\n  %early = load i8, ptr %self.0.val, align 1\n', 1)


def dependency_mutants(case):
    begin, _ = check.beginning.select(case.core)
    yield 'missing actual initializer', replace(case, core=case.core.replace(begin, ''))
    yield 'initializer skips full destination erase', replace(case, core=case.core.replace(begin, begin.replace(' %region.1)', ' 0)')))
    yield 'initializer retains old initialized length', replace(case, core=case.core.replace(begin, begin.replace('store i64 0,', 'store i64 1,')))
    yield 'nonvolatile core clearing', replace(case, core=case.core.replace('store volatile i8 0,', 'store i8 0,'))
    yield 'wrong clearing assembly architecture', replace(case, arm=not case.arm)
    definitions = check.comparison.definitions(case.sha3)
    wipe = definitions[check.readers.staging.unique(definitions, 'accelerated', '6Memory4wipe')]
    yield 'missing actual memory wipe', replace(case, sha3=case.sha3.replace(wipe, ''))
    yield 'truncated actual memory wipe', replace(case, sha3=case.sha3.replace(wipe, wipe.replace('i64 noundef 200', 'i64 noundef 199')))


def main(record):
    before = check.comparison.capture.sources()
    counts, controls, dependencies = [], 0, 0
    for case in check.readers.cases(record):
        function, *bound = check.bind(case)
        inspect = lambda body: check.inspect(body, *bound)
        labels = inspect(function)
        counts.append(rejects(inspect, function, mutants(function, labels)))
        for changed in (function.replace('start:\n', 'start:\n; harmless entry comment\n', 1),
                        re.sub(r'%\d+(?![\w.])', lambda m: '%entry' + m[0][1:] if m[0] not in ('%0', '%1') else m[0], function)):
            assert changed != function
            inspect(changed)
            controls += 1
        dependencies += rejects(lambda value: check.inspect(*check.bind(value)), case, dependency_mutants(case))
    assert len(counts) == 8 and min(counts) > 100 and dependencies == 56 and controls == 16, (counts, dependencies, controls)
    assert before == check.comparison.capture.sources()
    print(f'Accelerated initialization rejects {sum(counts)} entry/transfer mutants and {dependencies} dependency mutants; {controls} controls PASS; per-path={counts}')
    print('Saved artifacts only; subprocess execution forbidden; production and release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
