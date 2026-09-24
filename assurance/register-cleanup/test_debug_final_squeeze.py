#!/usr/bin/env python3
"""Mutate retained final-bit control/data flow; no compiler or Rust execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_final_squeeze as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def boundaries():
    names = dict(final_squeeze='final', squeeze='prefix', fill='fill', first='first', apply_mask='mask',
                 output_write='write', copy='copy', staging_get='slice', writer='writer', counter='counter',
                 success=255, rate=168, panics=set())
    machine = check.FinalModel({}, '', names, 0, 2, 7)
    controls = rejected = 0

    def reject(name, args):
        try:
            machine.run(name, args)
        except ValueError:
            return 1
        raise AssertionError('malformed final-bit boundary accepted')

    for a in (0, 1, 7, 8, 255):
        for b in (0, 1, 7, 8, 255):
            assert machine.run('llvm.usub.sat.i8', [a, b]) == max(0, a - b)
            controls += 1
    for args in ([], [0], [0, -1], [256, 0], [check.model.UNKNOWN, 8]):
        rejected += reject('llvm.usub.sat.i8', args)
    correct = [check.model.Pointer('storage', 584), 127, 0]
    rejected += reject('mask', correct)
    machine.prefix_done = True
    assert machine.run('mask', correct) is None
    controls += 1
    for args in ([], [check.model.Pointer('storage', 585), 127, 0],
                 [check.model.Pointer('storage', 584), 255, 0], [check.model.Pointer('storage', 584), 127, 1]):
        rejected += reject('mask', args)
    rejected += reject('prefix', [check.model.Pointer('storage'), check.model.Pointer('owner'), 2])
    rejected += reject('final', [check.model.Pointer('storage'), 2, 8, check.model.Pointer('owner')])
    assert (controls, rejected) == (26, 12)
    print(f'Final-bit boundary model: {controls} controls; {rejected} malformed/unordered calls rejected', flush=True)


def mutants(case):
    names, selected, _ = check.closure(case)
    for name, body in selected.items():
        yield 'missing final-bit dependency: ' + name, changed(case, body, '')
    root = names['final_squeeze']
    body = selected[root]
    yield 'by-value final owner', changed(case, body, body.replace('(ptr ', '(ptr byval([1040 x i8]) ', 1))
    for label, lines in check.model.blocks(body).items():
        for index, line in enumerate(lines):
            alternatives = []
            symbol = re.search(check.comparison.SYMBOL, line)
            if symbol and 'call ' in line:
                callee = symbol[1]
                if callee in (names['squeeze'], names['fill'], names['apply_mask'], names['output_write'], names['clear']):
                    alternatives.append('')
                if callee == names['apply_mask']:
                    alternatives.append(line.replace(', i8 0)', ', i8 1)'))
                if callee == names['clear']:
                    alternatives.append(line.replace('i64 168', 'i64 167'))
                if callee == names['fill']:
                    alternatives.append(line.replace('i64 1)', 'i64 2)'))
            if found := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                alternatives.append(f'br i1 {found[1]}, label %{found[3]}, label %{found[2]}')
            if 'getelementptr' in line and line.endswith(', i64 584'):
                alternatives.append(line[:-3] + '585')
            for alternative in alternatives:
                assert alternative != line
                new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                yield label + '/' + line, changed(case, body, replace_block(body, label, new))
    bits = selected[names['bits']]
    for divisor in (0, 1, 16):
        replacement, count = re.subn(r'(udiv i128 %\S+, )8\b', r'\g<1>' + str(divisor), bits)
        assert count == 1
        yield 'wrong bit admission divisor', changed(case, bits, replacement)
    mask = selected[names['mask']]
    replacement = mask.replace('(i8 8,', '(i8 7,')
    assert replacement != mask
    yield 'wrong final mask', changed(case, mask, replacement)


def helpers(case):
    names, _, merged = check.closure(case)
    functions, constants = check.squeeze.begin.functions_and_constants(case, merged)
    controls = 0
    for valid in range(256):
        machine = check.FinalModel(functions, constants, names, 0, 0, 0)
        assert machine.run(names['mask'], [valid]) == (1 << min(valid, 8)) - 1
        controls += 1
        for length in (0, 1, 168, check.model.MASK):
            assert machine.run(names['complete'], [length, valid]) == (
                length if valid in (0, 8) else max(0, length - 1))
            controls += 1
        assert not machine.events and not machine.reads and not machine.writes
    assert controls == 1280
    return controls


def main(record, shard=None):
    boundaries()
    before = check.comparison.capture.sources()
    cases = list(check.squeeze.begin.guard.final.cases(record))
    assert len(cases) == 16 and (shard is None or shard in range(4))
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    counts, controls = [], 0
    for case in chosen:
        assert helpers(case) == 1280
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        names, selected, _ = check.closure(case)
        body = selected[names['final_squeeze']]
        replacement = re.sub(r'%output_bytes\b', '%destination_width', body)
        assert replacement != body
        check.inspect(changed(case, body, replacement), False)
        controls += 1
        print('Final-bit mutations: ' + str(counts[-1]), flush=True)
    assert len(counts) == len(chosen) and min(counts) >= 25 and controls == len(chosen)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; paths {4 * shard}..{4 * shard + 3}'))
    print(f'Final-bit squeeze rejects {sum(counts)} dependency/ABI/mask/admission/cleanup regressions; {controls} SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Subprocess execution forbidden; opaque secret primitives and final outer-guard composition remain unqualified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4), help='only this quarter of the matrix; all four are required')
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
