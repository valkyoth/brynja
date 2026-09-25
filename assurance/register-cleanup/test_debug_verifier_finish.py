#!/usr/bin/env python3
"""Mutation-test actual finish decisions and composed reader/guard transfer."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_verifier_finish as check
from debug_verifier_finish import guard
from test_debug_accelerated_model import rejects
from test_kmac_optimized_cleanup import replace_block

SSA = guard.SSA


def mutations(body):
    for label, lines in check.model.blocks(body).items():
        for index, line in enumerate(lines):
            if '.dbg.spill' in line:
                continue
            changes = []
            if 'getelementptr inbounds i8' in line:
                changes.append(re.sub(r'i64 (\d+)$', lambda m: 'i64 ' + str(int(m[1]) + 1), line))
            if line.startswith('store i8 '):
                changes.append(re.sub(r'^store i8 (\d+),', lambda m: 'store i8 ' + str(int(m[1]) ^ 1) + ',', line))
            if line.startswith('store ptr %'):
                changes.append(re.sub(r'^store ptr ' + SSA + ',', 'store ptr null,', line))
            if 'icmp ult ' in line:
                changes.append(line.replace('icmp ult ', 'icmp ule '))
            if 'icmp eq ' in line:
                changes.append(line.replace('icmp eq ', 'icmp ne '))
            if '@llvm.memcpy.' in line:
                changes.append(re.sub(r'i64 (16|24|32), i1 false', lambda m: 'i64 ' + str(int(m[1]) - 1) + ', i1 false', line))
            if 'call ' in line or 'invoke ' in line:
                name, args = guard.call(line)
                for arg in args:
                    if re.search(SSA + '$', arg):
                        changes.append(line.replace(arg, re.sub(SSA + '$', '%foreign', arg), 1))
                if 'drop_in_place' in name or 'drop_glue' in name:
                    if line.startswith('invoke '):
                        yield label + '/missing unwind cleanup', replace_block(body, label, lines[:index] +
                            ['br label %' + guard.successors(lines)[0][0]])
                    else:
                        yield label + '/missing normal cleanup', replace_block(body, label, lines[:index] + lines[index + 1:])
            if line.startswith('br i1 '):
                condition, yes, no = re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line).groups()
                changes.append(f'br i1 {condition}, label %{no}, label %{yes}')
            for changed in changes:
                if changed != line:
                    yield label + '/' + line, replace_block(body, label, lines[:index] + [changed] + lines[index + 1:])


def boundaries():
    p = check.model.Pointer
    roles = {role: role for role in ('none', 'key', 'ne', 'suffix', 'core_drop', 'state_drop')}
    def machine():
        m = check.FinishModel({}, {'CLEAR': 'clear'}, roles, {'@full': 0}, 32, 24, (True, True, 128, 128, True, None, 1))
        m.allocate('core', 24)
        m.allocate('metadata', 98, payload=True)
        m.allocate('local', 32)
        return m
    actions = [lambda role=role: machine().run(role, [p('core', 1)]) for role in ('none', 'key', 'core_drop', 'state_drop')]
    actions += [lambda: machine().load(p('metadata', 32), 1),
                lambda: machine().store(p('metadata', 32), 1, 0),
                lambda: machine().run('llvm.memcpy.p0.p0.i64', [p('local'), p('metadata', 32), 24, 0]),
                lambda: machine().run('llvm.memcpy.p0.p0.i64', [p('local'), p('local'), 24, 0]),
                lambda: machine().run('llvm.memcpy.p0.p0.i64', [p('local'), p('core'), 23, 0]),
                lambda: machine().run('ne', [p('local'), p('core')]),
                lambda: machine().run('suffix', [p('local'), p('core', 9), p('local'), 128]),
                lambda: machine().run('suffix', [p('local'), p('core', 8), p('local'), 127])]
    assert sum(rejects(action) for action in actions) == 12
    print('Twelve finish contract/payload/copy regressions rejected', flush=True)


def main(record):
    boundaries()
    before = check.comparison.capture.sources()
    count = controls = builds = 0
    for function, definitions, names, text, errors in check.cases(record):
        root, _, _, helpers, _ = check.closure(function, definitions, names, text)
        baseline = check.inspect(function, definitions, names, text, errors, fast=True)
        body = definitions[root]
        for label, changed in mutations(body):
            try:
                count += rejects(lambda: check.inspect(function, {**definitions, root: changed}, names, text, errors, fast=True))
            except AssertionError as error:
                raise AssertionError('accepted finish mutation: ' + label) from error
        for name in helpers:
            if name == 'fragment' or name == root:
                continue
            changed = definitions[name].splitlines()[0] + '\nstart:\n  ret void\n}'
            count += rejects(lambda: check.inspect(function, {**definitions, name: changed}, names, text, errors, fast=True))
        for changed in (re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), body),
                        re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M)):
            assert changed != body and check.inspect(function, {**definitions, root: changed}, names, text, errors, fast=True) == baseline
            controls += 1
        builds += 1
        print(f'Finish mutations: {builds}/24 paths; {count} rejected', flush=True)
    assert (builds, controls, count) == (24, 48, 1392) and before == check.comparison.capture.sources()
    print(f'Debug verifier finish: {count} body/helper mutations rejected; {controls} label/metadata controls PASS')
    print('Retained-artifact diagnostics only; explicit producer/destructor contracts, not whole-verifier/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
