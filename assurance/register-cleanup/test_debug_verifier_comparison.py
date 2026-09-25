#!/usr/bin/env python3
"""Fail-closed retained debug comparison caller regressions; no subprocesses."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_verifier_comparison as check
from debug_verifier_comparison import guard, SSA
from test_kmac_optimized_cleanup import replace_block
from test_debug_accelerated_model import rejects


def mutations(function, definitions):
    _, _, roles, functions, stops = check.extract(function, definitions)
    graph = check.model.blocks(function)
    # LLVM retains unused Option tuple reloads in debug builds. They are not
    # semantic comparison regressions; exclude their dead SSA chains.
    instructions = [line for lines in graph.values() for line in lines]
    dead = set()
    while True:
        used = set(re.findall(SSA, '\n'.join(line.split(' = ', 1)[-1] for line in instructions
                                            if line.split(' = ', 1)[0] not in dead)))
        added = {line.split(' = ', 1)[0] for line in instructions
                 if ' = ' in line and line.split(' = ', 1)[0] not in used
                 and not any(token in line for token in ('invoke ', 'call ', 'alloca '))}
        if added <= dead:
            break
        dead.update(added)
    for label, selected in functions['fragment'][1].items():
        if label == 'start' or selected == ['unreachable']:
            continue
        lines = graph[label]
        for index, line in enumerate(lines):
            if line.split(' = ', 1)[0] in dead or '.dbg.spill' in line:
                continue
            changes = []
            if 'getelementptr inbounds i8' in line:
                changes.append(re.sub(r'i64 (\d+)$', lambda m: 'i64 ' + str(int(m[1]) + 1), line))
            if '@llvm.memcpy.' in line:
                changes.append(re.sub(r'i64 (24|48), i1 false', lambda m: 'i64 ' + str(int(m[1]) - 1) + ', i1 false', line))
            if 'icmp eq ' in line:
                changes.append(line.replace('icmp eq ', 'icmp ne ', 1))
            if ' = load ptr,' in line or ' = load i8,' in line:
                # Debug spill writes are not reads: only reached semantic loads.
                changes.append(re.sub(r'ptr ' + SSA + ', align', 'ptr %cleanup, align', line))
            if 'invoke ' in line:
                name, args = guard.call(line)
                if name in roles.values() and name != roles['error']:
                    for arg in args:
                        if re.search(SSA + '$', arg):
                            changed = re.sub(SSA + '$', '%foreign', arg)
                            changes.append(line.replace(arg, changed, 1))
                if name == roles['accumulate']:
                    changes.append('br label %' + guard.successors(lines)[0][0])
            if line.startswith('br i1 '):
                condition, yes, no = re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line).groups()
                changes.append(f'br i1 {condition}, label %{no}, label %{yes}')
            for changed in changes:
                if changed == line:
                    continue
                mutated = lines[:index] + [changed] + lines[index + 1:]
                if changed.startswith('br label ') and 'invoke ' in line:
                    mutated = mutated[:-1]
                yield label + '/' + line, replace_block(function, label, mutated)


def boundaries():
    p = check.model.Pointer
    m = check.ComparisonModel({}, {}, 0, 1, 1)
    m.allocate('secret', 66, payload=True)
    m.allocate('local', 48)
    actions = (
        lambda: m.load(p('secret'), 1), lambda: m.store(p('secret'), 1, 0),
        lambda: m.move(p('local'), p('secret'), 24),
        lambda: m.move(p('secret'), p('local'), 24),
        lambda: m.move(p('local'), p('local'), 24),
        lambda: m.move(p('local'), p('local'), 23),
        lambda: m.run('llvm.memcpy.p0.p0.i64', [p('local'), p('secret'), 24, 1]),
        lambda: m.run('unknown', []),
    )
    assert sum(rejects(action) for action in actions) == 8
    print('Eight direct payload, alias, copy-width and unknown-callee regressions rejected', flush=True)


def main(record):
    boundaries()
    before = check.comparison.capture.sources()
    builds = count = controls = 0
    for function, definitions, errors in check.cases(record):
        baseline = check.inspect(function, definitions, errors)
        for label, mutated in mutations(function, definitions):
            try:
                count += rejects(lambda: check.inspect(mutated, definitions, errors))
            except AssertionError as error:
                raise AssertionError('accepted caller mutation: ' + label) from error
        _, _, roles, _, _ = check.extract(function, definitions)
        branch = roles['branch']
        body = definitions[branch]
        for changed in (
            body.splitlines()[0] + '\nstart:\n  ret void\n}',
            body.replace('icmp eq ', 'icmp ne ', 1),
        ):
            assert changed != body
            count += rejects(lambda: check.inspect(function, {**definitions, branch: changed}, errors))
        for changed in (
            re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
            re.sub(r'^\s*#dbg_.*\n', '', function, flags=re.M),
        ):
            assert changed != function and check.inspect(changed, definitions, errors) == baseline
            controls += 1
        builds += 1
        print(f'Comparison mutations: {builds}/24 fragments; {count} rejected', flush=True)
    assert (builds, controls, count) == (24, 48, 1008) and before == check.comparison.capture.sources()
    print(f'Debug verifier comparison: {count} caller IR regressions rejected; {controls} label/metadata controls PASS')
    print('Iterator and reader contracts are explicit; no runtime, whole-verifier or F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
