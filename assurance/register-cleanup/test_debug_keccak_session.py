#!/usr/bin/env python3
"""Mutation/boundary tests for retained static Keccak session metadata."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_keccak_session as check
from test_kmac_optimized_cleanup import replace_block
from test_debug_accelerated_model import rejects


def changed(case, body, new):
    assert body != new
    fields = {key: getattr(case, key).replace(body, new) for key in ('cpu', 'core', 'sha3') if body in getattr(case, key)}
    assert fields
    return replace(case, **fields)


def mutants(case, visited):
    names, selected = check.closure(case)
    roles = {names[role] for role in ('check', 'permute', 'authority', 'quarantine', 'dispatch', 'scratch')}
    roles.update(name for name in selected if any(token in name for token in ('21check_compiled_target', '14check_hardened',
                                                                            '19quarantine_hardened')))
    roles.update(name for name in selected if 'Operation' in name and '4drop' in name)
    for name in sorted(roles):
        body = selected[name]
        yield 'missing required helper', changed(case, body, '')
        yield 'by-value helper ABI', changed(case, body, body.replace('ptr ', 'ptr byval([32 x i8]) ', 1)) if 'ptr ' in body else changed(
            case, body, body.replace('i8 %self', 'ptr byval([32 x i8]) %self', 1))
        for label, lines in check.model.blocks(body).items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                if line.startswith('br i1 '):
                    parts = re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line)
                    assert parts
                    alternatives.append(f'br i1 {parts[1]}, label %{parts[3]}, label %{parts[2]}')
                if 'icmp ne i64' in line:
                    alternatives.append(line.replace('icmp ne', 'icmp eq'))
                if line.startswith('store i8 ') and re.search(r'store i8 (-?\d+),', line):
                    match = re.search(r'store i8 (-?\d+),', line)
                    alternatives.append(line.replace(match[0], f'store i8 {0 if int(match[1]) else 1},', 1))
                if name == names['scratch'] and 'getelementptr' in line:
                    alternatives.append(re.sub(r'i64 (\d+)$', lambda m: 'i64 ' + str(int(m[1]) + 1), line))
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and re.search(r'\b(?:call|invoke) ', line):
                    args = check.comparison.arguments(line, symbol.end())
                    for arg in args:
                        if arg.startswith('ptr ') and not re.search(r'@(?:alloc|anon)[_.]', arg):
                            alternatives.append(line.replace(arg, 'ptr null', 1))
                    if line.startswith('call void '):
                        alternatives += ['', line + '\n' + line]
                    if name == names['scratch']:
                        alternatives.append('')  # clear result is ignored, but clearing must happen.
                        alternatives.append(re.sub(r'i64 \d+\)', 'i64 0)', line))
                if line.startswith('resume { ptr, i32 }'):
                    alternatives.append('ret i8 ' + str(names['success']))
                if line.startswith('invoke ') and 'panic_in_cleanup' not in line:
                    edge = re.fullmatch(r'to label %(\S+) unwind label %(\S+)', lines[index + 1])
                    assert edge
                    new = lines[:index] + ['br label %' + edge[1]] + lines[index + 2:]
                    yield 'skipped invoked handoff', changed(case, body, replace_block(body, label, new))
                for alternative in alternatives:
                    assert alternative != line
                    new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                    unused_feature = ('21check_compiled_target' in name and line.startswith('store i8 ')
                                      and ', ptr %_4,' not in line and 'store i8 0, ptr %_4, align 1' in lines)
                    prefix = 'control: feature bit after rejected architecture/' if unused_feature else ''
                    yield prefix + name + '/' + label + '/' + line, changed(case, body, replace_block(body, label, new))


def boundaries():
    names = dict(authority='authority', quarantine='quarantine', kernel='kernel', wipe='wipe')
    def machine(functions=None):
        return check.SessionModel(functions or {}, '', names, 4, 1, 2, 2, 7, None)
    p = check.model.Pointer
    count = 0
    for action in (
            lambda m: m.load(p('session'), 8), lambda m: m.load(p('state'), 1),
            lambda m: m.load(p('session', 576), 1), lambda m: m.store(p('session'), 1, 0),
            lambda m: m.store(p('authority', 9), 1, 4), lambda m: m.store(p('authority'), 8, 2),
            lambda m: m.run('kernel', [p('session', 32), p('state')]),
            lambda m: m.run('kernel', [p('session'), p('session')]),
            lambda m: m.run('wipe', [p('session'), 199]), lambda m: m.run('wipe', [p('state'), 200]),
            lambda m: m.run('authority', [p('authority'), 1]), lambda m: m.run('quarantine', [p('session')])):
        count += rejects(lambda: action(machine()))
    functions = {'xor': (['%a', '%b'], {'start': ['%c = xor i1 %a, %b', 'ret i1 %c']})}
    for a in (0, 1):
        for b in (0, 1):
            assert machine(functions).run('xor', [a, b]) == a ^ b
    count += rejects(lambda: machine(functions).run('xor', [check.model.UNKNOWN, 1]))
    assert machine().value('{ i1 true, i8 poison }', {}) == (1, check.model.UNKNOWN)
    assert machine().value('{ i1 false, i8 poison }', {}) == (0, check.model.UNKNOWN)
    assert count == 13
    print('Static session boundary: thirteen payload/alias/owner/poison regressions rejected; four XOR and two aggregate controls PASS', flush=True)


def main(record, shard):
    boundaries()
    before = check.comparison.capture.sources()
    cases = list(check.cases(record))
    assert len(cases) == 4
    for case in cases if shard is None else [cases[shard]]:
        _, _, visited = check.inspect(case)
        count = controls = 0
        for label, mutant in mutants(case, visited):
            if label.startswith('control:'):
                assert check.inspect(mutant)[0] == 200
                controls += 1
                continue
            try:
                check.inspect(mutant)
            except ValueError:
                count += 1
            else:
                raise AssertionError('accepted session regression: ' + label)
        names, selected = check.closure(case)
        body = selected[names['permute']]
        for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M), re.sub(r'%guard\b', '%operation_guard', body)):
            assert check.inspect(changed(case, body, control))[0] == 200
        assert (count, controls) == ((114, 3) if case.arm else (115, 2))
        print(f'Static session {case.compiler} arm={case.arm}: {count} mutations rejected; two SSA/metadata and {controls} inactive-feature controls PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all four builds' if shard is None else f'shard {shard}/4; all four required'))
    print('Retained metadata only; no compiler/runtime subprocesses or whole-call/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
