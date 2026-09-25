#!/usr/bin/env python3
"""Focused retained-IR regressions at the engine/outer-reader composition links."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_composed_read as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block


def cases_for_mutations(thorough, consuming):
    # Multiple chunks, plus rejection/unwind after an already committed prefix.
    for session, fault, outer in ((None, None, None), ((3, 2), None, None), ((3, 'unwind'), None, None),
                                  (None, (2, ('copy', 1, 2)), None),
                                  (None, (2, ('permute', 1, 'unwind')), None),
                                  (None, (2, ('writer', 0, 'unwind')), None),
                                  (None, None, ('copy', 2, 'unwind'))):
        yield 505, 7, 3, 72, 72, 0, 1, session, fault, outer


def mutants(case, consuming):
    root, _, names, merged = check.closure(case, consuming)
    for caller, callee, argument, replacement in (
            ('operation', 'read', 0, 'ptr null'), ('operation', 'read', 1, 'ptr null'),
            ('operation', 'read', 2, 'i64 1'), ('operation', 'preflight', 1, 'i64 1'),
            ('read', 'preflight', 1, 'i64 0'), ('read', 'writer', 1, 'i128 0'),
            ('read', 'lane_copy', 0, 'ptr null')):
        body = merged[names[caller]]
        lines = [line for line in body.splitlines() if re.search(r'\b(?:call|invoke) ', line)
                 and names[callee] + '(' in line]
        assert len(lines) == 1
        line = lines[0]
        symbol = re.search(check.comparison.SYMBOL, line)
        args = check.comparison.arguments(line, symbol.end())
        assert args[argument] != replacement
        yield f'{caller}/{callee} wrong argument {argument}', changed(case, body, body.replace(line, line.replace(args[argument], replacement)))
    for role, target in (('operation', 'read'), ('read', 'writer'), ('read', 'preflight')):
        body = merged[names[role]]
        found = 0
        for label, lines in check.model.blocks(body).items():
            for index, line in enumerate(lines):
                if 'invoke ' not in line or names[target] + '(' not in line:
                    continue
                found += 1
                edge = re.fullmatch(r'to label %(\S+) unwind label %(\S+)', lines[index + 1])
                assert edge
                # Preserve a well-formed scalar result while skipping execution.
                assign = re.match(r'(%\S+) = invoke i8 ', line)
                prefix = [assign[1] + f' = add i8 {names["success"]}, 0'] if assign else []
                skipped = lines[:index] + prefix + ['br label %' + edge[1]] + lines[index + 2:]
                yield role + '/' + target + ' skipped', changed(case, body, replace_block(body, label, skipped))
                wrong_unwind = lines[:index + 1] + ['to label %' + edge[1] + ' unwind label %' + edge[1]] + lines[index + 2:]
                yield role + '/' + target + ' lost unwind cleanup', changed(case, body, replace_block(body, label, wrong_unwind))
        assert found == 1
    for role, body in (('outer', merged[root]), ('engine', merged[names['read']])):
        for label, lines in check.model.blocks(body).items():
            for index, line in enumerate(lines):
                if line.startswith('resume { ptr, i32 }'):
                    yield role + ' lost exception', changed(case, body, replace_block(body, label, lines[:index] + ['ret void'] + lines[index + 1:]))


def main(record, shard):
    before = check.comparison.capture.sources()
    cases = list(check.operation.cases(record))
    assert len(cases) == 8
    for case in cases if shard is None else [cases[shard]]:
        for consuming in (False, True):
            count = 0
            with patch.object(check, 'scenarios', cases_for_mutations):
                assert check.inspect(case, False, consuming)[0] == 7
                for label, mutant in mutants(case, consuming):
                    try:
                        check.inspect(mutant, False, consuming)
                    except ValueError:
                        count += 1
                    else:
                        raise AssertionError('accepted composed-read regression: ' + label)
                _, _, names, merged = check.closure(case, consuming)
                body = merged[names['read']]
                for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M),
                                re.sub(r'%operation\b', '%read_guard', body)):
                    assert control != body
                    assert check.inspect(changed(case, body, control), False, consuming)[0] == 7
            assert count >= 14
            print(f'Composed read {consuming=}: {count} IR mutations rejected; two controls PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all eight paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Compiler/runtime subprocesses forbidden; primitive and whole-call qualification still pending')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
