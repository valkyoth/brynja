#!/usr/bin/env python3
"""Retained final-byte caller/helper mutations, without compiler subprocesses."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_verifier_final_comparison as check
import test_debug_verifier_comparison as bulk_tests
from test_debug_accelerated_model import rejects


def boundaries():
    p = check.model.Pointer
    def machine(length=1):
        m = check.FinalModel({}, {'first': 'first', 'accumulate': 'accumulate'}, 32, length, 63)
        m.allocate('metadata', 98, payload=True)
        m.allocate('candidate', 96, payload=True)
        m.allocate('empty', 0, payload=True)
        return m
    actions = (
        lambda: machine().run('first', [p('metadata', 33), 1]),
        lambda: machine().run('first', [p('metadata', 32), 0]),
        lambda: machine(2).run('first', [p('metadata', 32), 2]),
        lambda: machine().run('accumulate', [p('metadata', 96), p('metadata', 32), p('candidate', 95)]),
        lambda: machine().run('accumulate', [p('metadata', 97), p('metadata', 33), p('candidate', 95)]),
        lambda: machine().run('accumulate', [p('metadata', 97), p('metadata', 32), p('candidate', 32)]),
        lambda: machine(0).run('accumulate', [p('metadata', 97), p('metadata', 32), p('candidate', 95)]),
        lambda: machine().load(p('metadata', 32), 1),
        lambda: machine().store(p('metadata', 32), 1, 0),
    )
    assert sum(rejects(action) for action in actions) == 9
    m = machine()
    args = [p('metadata', 97), p('metadata', 32), p('candidate', 95)]
    m.run('accumulate', args)
    assert rejects(lambda: m.run('accumulate', args)) == 1
    assert machine(0).run('first', [p('empty'), 0]) == 0
    print('Ten final-byte pointer/length/payload/duplicate regressions rejected; empty-slice control PASS', flush=True)


def main(record):
    boundaries()
    before = check.comparison.capture.sources()
    count = controls = builds = 0
    for function, definitions, errors in check.cases(record):
        baseline = check.inspect(function, definitions, errors)
        # Reuse the mutation generator, not the bulk extractor or oracle.
        with patch.object(bulk_tests, 'check', check):
            variants = list(bulk_tests.mutations(function, definitions))
        for label, mutated in variants:
            try:
                count += rejects(lambda: check.inspect(mutated, definitions, errors))
            except AssertionError as error:
                raise AssertionError('accepted final caller mutation: ' + label) from error
        _, _, roles, _, _ = check.extract(function, definitions)
        for role in ('branch', 'first_branch', 'option'):
            name = roles[role]
            body = definitions[name]
            changed = body.splitlines()[0] + '\nstart:\n  ret void\n}'
            count += rejects(lambda: check.inspect(function, {**definitions, name: changed}, errors))
        # Corrupt the actual empty-output error value, not an oracle-derived input.
        option_lines = [line for lines in check.model.blocks(function).values() for line in lines
                        if 'invoke ' in line and roles['option'] in line and line.endswith(', i8 ' + str(5 if errors == 7 else 17) + ')')]
        assert len(option_lines) == 1
        changed = function.replace(option_lines[0], re.sub(r'i8 \d+\)$', 'i8 0)', option_lines[0]), 1)
        count += rejects(lambda: check.inspect(changed, definitions, errors))
        for changed in (
            re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
            re.sub(r'^\s*#dbg_.*\n', '', function, flags=re.M),
        ):
            assert changed != function and check.inspect(changed, definitions, errors) == baseline
            controls += 1
        builds += 1
        print(f'Final comparison mutations: {builds}/24 fragments; {count} rejected', flush=True)
    assert (builds, controls, count) == (24, 48, 912) and before == check.comparison.capture.sources()
    print(f'Debug verifier final comparison: {count} caller/helper regressions rejected; {controls} label/metadata controls PASS')
    print('Retained diagnostics only; no compiler/runtime reruns or whole-verifier/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
