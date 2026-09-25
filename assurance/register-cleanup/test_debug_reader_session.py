#!/usr/bin/env python3
"""Focused actual-IR mutations and opaque-payload boundaries for CPU/readers."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_reader_session as check
from debug_reader_session import SessionReader, model
from test_debug_accelerated_model import rejects


def one_case(thorough, consuming):
    yield 1, 7, 3, 136, 136, 0, 1, (1, 3), None, None
    # One real permutation with the original exception through CPU/engine/reader
    # guards; all scratch, engine and output clearing must still complete.
    yield 1, 7, 3, 136, 136, 0, 1, None, (1, ('permute', 1, 'unwind')), None


def mutants(case):
    names, selected = check.cpu.closure(case)
    for role in ('check', 'permute', 'authority', 'quarantine', 'dispatch', 'scratch'):
        body = selected[names[role]]
        result = 'void' if role in ('quarantine', 'scratch') else 'i8 ' + str(names['success'])
        replacement = body.splitlines()[0] + '\nstart:\n  ret ' + result + '\n}'
        assert replacement != body
        yield 'bypassed ' + role, replace(case, cpu=case.cpu.replace(body, replacement))
    body = selected[names['scratch']]
    modified, n = re.subn(r'i64 200\)', 'i64 199)', body, count=1)
    assert n == 1
    yield 'short CPU scratch clear', replace(case, cpu=case.cpu.replace(body, modified))
    body = selected[names['dispatch']]
    kernel = next(line for line in body.splitlines() if names['kernel'] + '(' in line)
    arguments = check.comparison.arguments(kernel, re.search(check.comparison.SYMBOL, kernel).end())
    assert len(arguments) == 2 and arguments[0].startswith('ptr ')
    modified = kernel.replace(arguments[0], 'ptr null', 1)
    yield 'wrong kernel borrow', replace(case, cpu=case.cpu.replace(body, body.replace(kernel, modified)))
    body = selected[names['permute']]
    modified, n = re.subn(r'resume \{ ptr, i32 \} %[-.$\w]+', 'ret i8 ' + str(names['success']), body)
    assert n == 1
    yield 'lost original kernel exception', replace(case, cpu=case.cpu.replace(body, modified))


def boundary_machine():
    m = object.__new__(SessionReader)
    model.Model.__init__(m, {}, '', '')
    m.cpu_active, m.clearing, m.primitive = True, None, None
    m.cpu_frame_start, m.frames = 2, 4
    m.cpu_events, m.cpu_records, m.clear_requests = [], [], []
    m.owner, m.generation = model.Pointer('authority'), 2
    m.names = {'cpu_roles': {'authority': 'authority', 'quarantine': 'quarantine', 'kernel': 'kernel'},
               'wipe': 'wipe', 'clear_precondition': 'precondition'}
    m.allocate('storage', 1088, payload=True)
    m.allocate('authority', 16)
    m.allocate('1:caller', 8)
    m.allocate('3:helper', 8)
    return m


def boundaries():
    p = model.Pointer
    actions = (
        lambda m: m.load(p('storage'), 1), lambda m: m.load(p('storage', 656), 8),
        lambda m: m.load(p('storage', 576), 1), lambda m: m.store(p('storage', 616), 8, 0),
        lambda m: m.store(p('1:caller'), 8, 0), lambda m: m.store(p('authority', 9), 1, 4),
        lambda m: m.run('authority', [p('authority'), 1]),
        lambda m: m.run('quarantine', [p('storage')]),
        lambda m: m.run('kernel', [p('storage'), p('storage', 657)]),
        lambda m: m.run('wipe', [p('storage', 576), 32]),
        lambda m: m.run('wipe', [p('storage'), 199]),
        lambda m: m.cpu_call('check', [], 0, 'check', 7),
    )
    assert sum(rejects(lambda: action(boundary_machine())) for action in actions) == 12
    m = boundary_machine()
    assert m.load(p('storage', 576), 8) == m.owner and m.load(p('storage', 584), 8) == 2
    m.store(p('3:helper'), 8, 42)
    assert model.Model.load(m, p('3:helper'), 8) == 42
    print('Twelve CPU/reader alias, payload, frame and recursion regressions rejected; metadata controls PASS', flush=True)


def main(record, shard):
    boundaries()
    before = check.comparison.capture.sources()
    pairs = list(check.cases(record))
    for case, cpu_case in pairs if shard is None else [pairs[shard]]:
        with patch.object(check, 'scenarios', one_case):
            assert check.inspect(case, cpu_case, True)[0] == 2
            count = 0
            for label, mutant in mutants(cpu_case):
                try:
                    check.inspect(case, mutant, True)
                except ValueError:
                    count += 1
                else:
                    raise AssertionError('accepted CPU/reader mutation: ' + label)
            names, selected = check.cpu.closure(cpu_case)
            body = selected[names['permute']]
            for modified in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M), re.sub(r'%guard\b', '%cpu_guard', body)):
                assert modified != body
                assert check.inspect(case, replace(cpu_case, cpu=cpu_case.cpu.replace(body, modified)), True)[0] == 2
        assert count == 9
        print('Reader/session composition: nine IR mutants rejected; two SSA/metadata controls PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all eight paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Retained artifacts only; compiler/runtime subprocesses forbidden; F1 remains open')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
