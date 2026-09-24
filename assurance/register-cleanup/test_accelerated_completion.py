#!/usr/bin/env python3
"""Mutate retained accelerated completion results, ownership and cleanup."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_accelerated_completion as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutants(function, names, labels):
    graph = check.staging.graph(function)
    for label in labels:
        lines = graph[label]
        for index, line in enumerate(lines):
            yield 'removed completion operation', replace_block(function, label, lines[:index] + lines[index + 1:])
            changes = []
            if 'getelementptr' in line and re.search(r'i64 \d+$', line):
                changes.append(('wrong owned field', re.sub(r'i64 (\d+)$', lambda m: 'i64 ' + str(int(m[1]) + 1), line)))
            if line.startswith('store '):
                changes.append(('redirected result/state store', re.sub(r', ptr ' + check.SSA + ',', ', ptr %foreign,', line)))
                if re.match(r'store i(?:8|64) \d+,', line):
                    changes.append(('wrong lifecycle/result discriminator', re.sub(r'(store i(?:8|64) )(\d+),', lambda m: m[1] + str(int(m[2]) + 1) + ',', line)))
            if ' load ' in line:
                changes.append(('foreign ownership/result load', re.sub(r', ptr ' + check.SSA + ',', ', ptr %foreign,', line)))
            if 'phi ' in line:
                changes.append(('forged phi input', re.sub(r'\[ [^,]+,', '[ %foreign,', line, count=1)))
            if ' call ' in ' ' + line or ' invoke ' in ' ' + line:
                name, args = check.adapter.routes.guard.call(line)
                if name == 'llvm.memcpy.p0.p0.i64':
                    for old, new in (('i64 24,', 'i64 23,'), ('i64 24,', 'i64 25,'), (args[0], args[1]), (args[1], args[0])):
                        changes.append(('wrong ownership transfer', line.replace(old, new, 1)))
                elif not name.startswith('llvm.'):
                    changes.append(('unbound completion/cleanup dependency', line.replace(name, 'foreign_callee')))
                    if name == names['finish']:
                        changes.extend((('wrong consumed descriptor', line.replace(args[1], args[1].replace(check.comparison.pointer(args[1]), '%foreign'))),
                                        ('incompatible finish result ABI', line.replace('sret([24 x i8])', 'sret([32 x i8])'))))
                    if name == names['guard']:
                        changes.extend((('completed guard on unwind', line.replace('i8 0', 'i8 1')),
                                        ('foreign guard owner', line.replace('%self.0.val', '%foreign'))))
            if line.startswith('resume '):
                changes += [('swallowed completion exception', 'ret void'), ('foreign resumed exception', 'resume { ptr, i32 } %foreign')]
            for reason, changed in changes:
                assert changed != line, reason
                yield reason, replace_block(function, label, lines[:index] + [changed] + lines[index + 1:])
        if lines[-1].startswith('br i1 '):
            branch = re.fullmatch(r'(br i1 .+), label %(.+), label %(.+)', lines[-1])
            yield 'inverted completion result', replace_block(function, label, lines[:-1] + [f'{branch[1]}, label %{branch[3]}, label %{branch[2]}'])
    for label in labels[1:6]:
        yield 'alternate completion entry', function[:-1] + 'bypass:\n  br label %' + label + '\n}'


def dependencies(case):
    finish = check.finishing.select(case.core)
    yield 'missing same-row finish', replace(case, core=case.core.replace(finish, ''))
    changed = re.sub(r'store ptr ' + check.SSA + r', ptr ', 'store ptr %foreign, ptr ', finish)
    yield 'foreign completed output pointer', replace(case, core=case.core.replace(finish, changed))
    for old, new in (('icmp eq i64', 'icmp ne i64'),
                     ('secret_memory_volatile23zeroize_region_volatile', 'foreign_erase')):
        yield 'broken finish ownership/clearing contract', replace(case, core=case.core.replace(finish, finish.replace(old, new)))
    yield 'nonvolatile core clearing', replace(case, core=case.core.replace('store volatile i8 0,', 'store i8 0,'))
    definitions = check.comparison.definitions(case.sha3)
    guard = check.staging.unique({name: body for name, body in definitions.items() if 'drop_in_place' in name or 'drop_glue' in name}, 'xof', 'Operation')
    body = definitions[guard]
    yield 'missing actual operation guard', replace(case, sha3=case.sha3.replace(body, ''))
    yield 'short actual guard staging clear', replace(case, sha3=case.sha3.replace(body, body.replace('[ 168, %start ]', '[ 167, %start ]')))
    yield 'wrong architecture clearing contract', replace(case, arm=not case.arm)


def main(record):
    before = check.comparison.capture.sources()
    counts, controls, bindings = [], 0, 0
    for case in check.readers.cases(record):
        function, names, compiler = check.bind(case)
        inspect = lambda body: check.inspect(body, names, compiler)
        labels = inspect(function)
        counts.append(rejects(inspect, function, mutants(function, names, labels)))
        for changed in (function.replace('start:\n', 'start:\n; harmless completion comment\n', 1),
                        re.sub(r'%\d+(?![\w.])', lambda m: '%completed' + m[0][1:] if m[0] not in ('%0', '%1') else m[0], function)):
            assert changed != function
            inspect(changed)
            controls += 1
        bindings += rejects(lambda value: check.inspect(*check.bind(value)), case, dependencies(case))
    assert counts == [114] * 4 + [115] * 4 and bindings == 64 and controls == 16, (counts, bindings, controls)
    assert before == check.comparison.capture.sources()
    print(f'Accelerated completion rejects {sum(counts)} LLVM and {bindings} dependency mutants; {controls} controls PASS; per-path={counts}')
    print('Saved artifacts only; subprocess execution forbidden; production and release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
