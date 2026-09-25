#!/usr/bin/env python3
"""Regression checks for complete KMAC control-flow composition."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_kmac_whole as check
import check_debug_kmac_suffix as suffix
from test_debug_accelerated_model import rejects
from test_kmac_optimized_cleanup import replace_block


def small_scenarios(_fast=False):
    for length, valid, present, strong, production, expected, mismatch, failure in (
            (130, 3, True, True, False, None, None, None), (65, 8, True, True, False, None, 64, None),
            (0, 0, True, True, False, None, None, None), (1, 8, False, True, False, None, None, None),
            (16, 8, True, False, True, None, None, None), (1, 8, True, True, True, None, None, None),
            (16, 8, True, True, False, 999, None, None), (130, 3, True, True, False, None, None, ('bulk', 3, 2)),
            (130, 3, True, True, False, None, None, ('final', 4))):
        yield length, valid, present, strong, production, expected, mismatch, failure


def probe(case):
    with patch.object(check, 'scenarios', small_scenarios):
        return check.inspect(*case, injections=False)


def no_op(body):
    header = body.splitlines()[0]
    kind = header.split(' @', 1)[0]
    if kind in ('define void', 'define internal void'):
        instructions = '  ret void'
    else:
        match = re.fullmatch(r'define \{ ptr, (i8|i64) }', kind)
        assert match, kind
        scalar = match[1]
        aggregate = '{ ptr, ' + scalar + ' }'
        instructions = ('  %empty = insertvalue ' + aggregate + ' undef, ptr null, 0\n'
                        '  %result = insertvalue ' + aggregate + ' %empty, ' + scalar + ' 0, 1\n'
                        '  ret ' + aggregate + ' %result')
    return header + '\nstart:\n' + instructions + '\n}'


def mutations(body):
    for label, lines in check.model.blocks(body).items():
        for index, line in enumerate(lines):
            if 'invoke ' not in line:
                continue
            name, args = check.destruction.guard.call(line)
            if any(part in name for part in ('33accumulate_secret_byte_difference', '12final_secret', '6secret')):
                normal = check.destruction.guard.successors(lines)[0][0]
                yield label + '/omitted operation', replace_block(body, label, lines[:index] + ['br label %' + normal])
            if '6chunks' in name:
                changed = line.replace('i64 64,', 'i64 63,')
                assert changed != line
                yield label + '/wrong chunk width', replace_block(body, label, lines[:index] + [changed] + lines[index + 1:])
            if '25secret_difference_is_zero' in name:
                changed = line.replace(args[0], 'ptr align 1 %self')
                yield label + '/wrong decision owner', replace_block(body, label, lines[:index] + [changed] + lines[index + 1:])


def boundaries():
    from debug_kmac_whole_model import WholeModel
    from debug_kmac_suffix import SuffixModel
    p = check.model.Pointer
    def machine(cls=WholeModel):
        m = cls({'drop_in_placeCshakeReader': ([], {}), 'drop_in_placeCshake': ([], {})},
                {'CLEAR': 'clear'}, {}, {}, False,
                (1, 8, True, True, False, None, None, None))
        m.allocate('a', 48)
        m.allocate('b', 48)
        m.allocate('metadata', 98, payload=True)
        return m
    m = machine()
    m.fields(p('a'), [(0, 8, p('metadata', 32)), (8, 8, 1)])
    m.move(p('b'), p('a'), 16)
    assert m.load(p('b'), 8) == p('metadata', 32) and m.load(p('b', 8), 8) == 1
    m.store(p('b'), 16, check.model.UNKNOWN)
    assert m.load(p('b', 8), 8) is check.model.UNKNOWN
    actions = [lambda: machine().move(p('a'), p('a'), 16),
               lambda: machine().move(p('a'), p('metadata', 32), 16),
               lambda: machine().move(p('a'), p('b'), 15),
               lambda: machine().load(p('metadata', 32), 1),
               lambda: machine().store(p('metadata', 32), 1, 0)]
    frame = machine(SuffixModel)
    frame.frame = frame.allocate('framing', 10)
    actions += [lambda: frame.load(p('framing', 8), 1), lambda: frame.store(p('framing', 8), 1, 0)]
    assert sum(rejects(action) for action in actions) == 7
    print('Seven model payload/copy boundaries reject; descriptor overwrite control PASS', flush=True)


def main(record):
    before = check.comparison.capture.sources()
    boundaries()
    counts = [0, 0, 0]
    for case in check.retained.cases(record):
        function, definitions, names, text = case
        baseline = probe(case)
        for label, changed in mutations(function):
            try:
                counts[0] += rejects(lambda: probe((changed, definitions, names, text)))
            except AssertionError as error:
                raise AssertionError('accepted whole-caller mutant: ' + label) from error
        _, helpers, _, _, _ = check.closure(*case)
        selected = [name for name in helpers if any(part in name for part in
                    ('Metadata4wipe', 'OwnedSecretRegion', 'as_deref_mut'))]
        for name in selected:
            changed = no_op(definitions[name])
            counts[0] += rejects(lambda: probe((function, {**definitions, name: changed}, names, text)))
        linked = suffix.closure(*case)
        for name in linked[1]:
            if name in helpers or not any(part in name for part in ('13append_suffix', 'Framing3new', 'Framing4wipe', '4take')):
                continue
            changed = no_op(definitions[name])
            counts[1] += rejects(lambda: suffix.inspect(function, {**definitions, name: changed}, names, text, fast=True))
        changed = re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function)
        assert changed != function and probe((changed, definitions, names, text)) == baseline
        counts[2] += 1
        print(f'Whole KMAC mutations: {counts[2]}/24 paths; caller={counts[0]}; suffix={counts[1]} PASS', flush=True)
    assert counts == [264, 96, 24], counts
    assert before == check.comparison.capture.sources()
    print('Whole KMAC mutation totals: ' + repr(tuple(counts)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
