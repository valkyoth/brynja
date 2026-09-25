#!/usr/bin/env python3
"""Mutate real retained destructor helpers and original cleanup handoffs."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_verifier_destructors as check
from debug_verifier_destructors import guard
from test_debug_accelerated_model import rejects
from test_debug_verifier_finish import mutations
from test_kmac_optimized_cleanup import replace_block


def boundaries():
    p = check.model.Pointer
    def machine():
        m = check.DestructorModel({}, {'CLEAR': 'clear'}, {'state_drop': 'state'}, 32, True)
        m.allocate('engine', 1120, payload=True)
        m.allocate('metadata', 98, payload=True)
        m.allocate('core', 64)
        return m
    actions = [lambda: machine().load(p('engine', 688), 8),
               lambda: machine().store(p('engine', 688), 8, 0),
               lambda: machine().store(p('engine', 891), 1, 0),
               lambda: machine().store(p('metadata', 32), 1, 0),
               lambda: machine().run('state', [p('core', 8)]),
               lambda: machine().run('clear', [p('engine', 689), 200]),
               lambda: machine().run('clear', [p('engine', 688), 199]),
               lambda: machine().run('clear', [p('core', 32), 64])]
    assert sum(rejects(action) for action in actions) == 8
    print('Eight destructor boundary/payload regressions rejected', flush=True)


def main(record):
    boundaries()
    before = check.comparison.capture.sources()
    count = controls = builds = 0
    for function, definitions, names, text in check.cases(record):
        roots, helpers, _ = check.closure(function, definitions, names, text)
        baseline = check.inspect(function, definitions, names, text)
        changes = []
        # Root control flow includes normal and exceptional metadata cleanup.
        for label, body in mutations(definitions[roots['core_drop']]):
            changes.append((roots['core_drop'], label, body))
        # Every helper must actually execute: a no-op anywhere in the chain
        # must change the independently expected clearing trace.
        for name in helpers:
            body = definitions[name]
            changes.append((name, 'no-op helper', body.splitlines()[0] + '\nstart:\n  ret void\n}'))
            for label, lines in check.model.blocks(body).items():
                stores = [line for line in lines if re.match(r'store i(?:8|64) [01],', line)]
                if stores:
                    assert len(stores) == 2 and lines[-1] == 'ret void'
                    changes.append((name, 'late cancellation flags', replace_block(body, label,
                        [line for line in lines[:-1] if line not in stores] + stores + [lines[-1]])))
                for index, line in enumerate(lines):
                    changed = None
                    if 'call ' in line and guard.call(line)[0] == names['CLEAR']:
                        changed = re.sub(r'i64 (\d+)\)', lambda m: 'i64 ' + str(int(m[1]) - 1) + ')', line)
                    elif line.startswith('br i1 '):
                        condition, yes, no = re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line).groups()
                        changed = f'br i1 {condition}, label %{no}, label %{yes}'
                    elif re.match(r'store i(?:8|64) [01],', line):
                        changed = re.sub(r'^(store i\d+) ([01]),', lambda m: m[1] + ' ' + str(1 - int(m[2])) + ',', line)
                    if changed is not None:
                        assert changed != line
                        changes.append((name, label + '/' + line, replace_block(body, label, lines[:index] + [changed] + lines[index + 1:])))
        for name, label, changed in changes:
            try:
                count += rejects(lambda: check.inspect(function, {**definitions, name: changed}, names, text))
            except AssertionError as error:
                raise AssertionError('accepted destructor mutation: ' + name + '/' + label) from error
        root = roots['core_drop']
        for changed in (re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), definitions[root]),
                        re.sub(r'^\s*#dbg_.*\n', '', definitions[root], flags=re.M)):
            assert changed != definitions[root]
            assert check.inspect(function, {**definitions, root: changed}, names, text) == baseline
            controls += 1
        builds += 1
        print(f'Destructor mutations: {builds}/24 paths; {count} rejected', flush=True)
    assert (builds, controls, count) == (24, 48, 888) and before == check.comparison.capture.sources()
    print(f'Debug verifier destructors: {count} IR mutations rejected; {controls} label/metadata controls PASS')
    print('Retained destructor request diagnostics, not physical erasure or whole-verifier/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
