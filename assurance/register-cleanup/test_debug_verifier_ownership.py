#!/usr/bin/env python3
"""Mutate retained post-finish transfer and actual result/guard helper bodies."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_verifier_ownership as check
from test_kmac_optimized_cleanup import replace_block
from test_debug_accelerated_model import rejects


def edits(body, labels, fragments=None):
    graph = check.model.blocks(body)
    for label in labels:
        lines = graph[label]
        for index, line in enumerate(lines):
            if fragments is not None and line not in fragments[label]:
                continue  # Later candidate work is deliberately outside this fragment.
            variants = []
            if 'getelementptr inbounds i8' in line:
                variants.append(re.sub(r'i64 (\d+)$', lambda m: 'i64 ' + str(int(m[1]) + 1), line))
            if '@llvm.memcpy.' in line:
                variants.append(re.sub(r'i64 (24|32), i1 false', lambda m: 'i64 ' + str(int(m[1]) - 1) + ', i1 false', line))
            if re.match(r'store ptr %', line):
                variants.append(re.sub(r'^store ptr %[-.$\w]+,', 'store ptr null,', line))
            if line.startswith('store i8 1,'):
                variants.append(line.replace('store i8 1,', 'store i8 0,', 1))
            if 'icmp eq ' in line:
                variants.append(line.replace('icmp eq ', 'icmp ne ', 1))
            if 'store i8 2,' in line:
                variants.append(line.replace('store i8 2,', 'store i8 0,', 1))
            for variant in variants:
                assert variant != line
                yield label + '/' + line, replace_block(body, label, lines[:index] + [variant] + lines[index + 1:])


def boundaries():
    p = check.model.Pointer
    def machine():
        m = check.OwnershipModel({}, {'CLEAR': 'clear'}, 32)
        m.allocate('metadata', 98, payload=True)
        m.allocate('descriptor', 32)
        m.allocate('other', 32)
        return m
    actions = (
        lambda m: m.load(p('metadata', 32), 1),
        lambda m: m.store(p('metadata', 32), 1, 0),
        lambda m: m.run('clear', [p('metadata'), 64]),
        lambda m: m.run('clear', [p('metadata', 32), 63]),
        lambda m: m.run('clear', [p('descriptor'), 64]),
        lambda m: m.run('llvm.memcpy.p0.p0.i64', [p('descriptor'), p('metadata', 32), 24, 0]),
        lambda m: m.run('llvm.memcpy.p0.p0.i64', [p('metadata', 32), p('descriptor'), 24, 0]),
        lambda m: m.run('llvm.memcpy.p0.p0.i64', [p('descriptor'), p('descriptor'), 24, 0]),
        lambda m: m.run('llvm.memcpy.p0.p0.i64', [p('descriptor'), p('other'), 23, 0]),
        lambda m: m.run('llvm.memcpy.p0.p0.i64', [p('descriptor'), p('other'), 24, 1]),
    )
    assert sum(rejects(lambda: action(machine())) for action in actions) == 10
    m = machine()
    m.store(p('other'), 8, p('metadata', 32))
    m.run('llvm.memcpy.p0.p0.i64', [p('descriptor'), p('other'), 24, 0])
    assert m.load(p('descriptor'), 8) == p('metadata', 32) and m.load(p('descriptor', 8), 8) is check.model.UNKNOWN
    print('Ten payload, alias, clear-region and move-width regressions rejected; undefined-padding control PASS', flush=True)


def main(record):
    boundaries()
    before = check.comparison.capture.sources()
    total = controls = builds = 0
    for function, definitions, names, errors in check.cases(record):
        baseline = check.inspect(function, definitions, names, errors)
        _, _, _, _, functions, labels, _ = check.extract(function, definitions, names)
        count = 0
        for label, mutated in edits(function, labels, functions['fragment'][1]):
            try:
                count += rejects(lambda: check.inspect(mutated, definitions, names, errors))
            except AssertionError as error:
                raise AssertionError('accepted selected caller mutation: ' + label) from error
        branch = next(name for name in functions if '6branch' in name)
        for label, mutated in edits(definitions[branch], check.model.blocks(definitions[branch])):
            count += rejects(lambda: check.inspect(function, {**definitions, branch: mutated}, names, errors))
        for role in ('GLUE', 'GUARD', 'WIPE'):
            body = definitions[names[role]]
            mutated = body.splitlines()[0] + '\nstart:\n  ret void\n}'
            count += rejects(lambda: check.inspect(function, {**definitions, names[role]: mutated}, names, errors))
        renamed = re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function)
        no_debug = re.sub(r'^\s*#dbg_.*\n', '', function, flags=re.M)
        for control in (renamed, no_debug):
            assert control != function and check.inspect(control, definitions, names, errors) == baseline
            controls += 1
        assert count >= 15
        total += count
        builds += 1
    assert (builds, controls, total) == (24, 48, 408) and before == check.comparison.capture.sources()
    print(f'Debug verifier ownership: {total} IR regressions rejected across {builds} fragments; {controls} metadata/label controls PASS')
    print('Retained artifacts only; no compiler/runtime subprocesses or whole-verifier/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
