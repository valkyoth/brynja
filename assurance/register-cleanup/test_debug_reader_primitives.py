#!/usr/bin/env python3
"""Mutations of retained split/copy/mask bodies, with no compiler subprocesses."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_reader_primitives as check
from test_debug_portable_final_bridge import changed
from test_debug_accelerated_model import rejects


def mutants(case):
    _, _, names, merged = check.closure(case, False)
    _, _, _, old = check.composed.closure(case, False)
    new = {name: body for name, body in merged.items() if name not in old}
    assert len(new) >= 6
    # Already present under output initialization, but newly exercised through
    # copy_secret_region here: include its length check and raw-leaf handoff.
    copies = {name: body for name, body in merged.items() if 'secret_memory_transfer4copy' in name}
    assert len(copies) == 1
    new.update(copies)
    for role in ('split', 'lane_copy', 'mask'):
        body = merged[names[role]]
        yield role + ' omitted', changed(case, body, '')
        yield role + ' by-value', changed(case, body, body.replace('ptr ', 'ptr byval([32 x i8]) ', 1))
    for name, body in new.items():
        if 'precondition_check' in name:
            continue  # Valid caller assumptions do not require redundant debug checks.
        for line in body.splitlines():
            stripped = line.strip()
            alternatives = []
            symbol = re.search(check.comparison.SYMBOL, line)
            if 'call ' in line and symbol and not stripped.startswith(';'):
                if symbol[1] in (names['raw_copy'], names['raw_mask']):
                    alternatives.append('')
                    args = check.comparison.arguments(line, symbol.end())
                    for index, value in ((0, 'ptr null'), (1, 'ptr null' if symbol[1] == names['raw_copy'] else 'i8 0'),
                                         (2, 'i64 0' if symbol[1] == names['raw_copy'] else 'i8 255')):
                        alternatives.append(line.replace(args[index], value))
                if 'llvm.memcpy' in line:
                    alternatives += ['', line.replace('i64 32', 'i64 16')]
            if 'icmp ule i64' in line:
                alternatives.append(line.replace('icmp ule', 'icmp ult'))
            if 'icmp ne i64' in line:
                alternatives.append(line.replace('icmp ne', 'icmp eq'))
            if 'sub nuw i64' in line:
                alternatives.append(line.replace('sub nuw', 'add nuw'))
            if 'getelementptr inbounds nuw i8, ptr %self.0, i64 %mid' in line:
                alternatives.append(line.replace('i64 %mid', 'i64 0'))
            for replacement in alternatives:
                assert replacement != line
                yield name + '/' + stripped, changed(case, body, body.replace(line, replacement))


def one_composed_case(thorough, consuming):
    assert consuming
    yield 505, 7, 3, 72, 72, 0, 1, None, None, None


def boundaries():
    names = dict(split='split', lane_copy='lane_copy', mask='mask', raw_parts='raw_parts', raw_copy='raw_copy', raw_mask='raw_mask')
    def machine():
        m = check.PrimitiveModel({}, '', names)
        m.allocate('payload', 1024, payload=True)
        m.allocate('result', 32)
        return m
    p = check.model.Pointer
    count = 0
    for role, args in (
            ('split', [p('result'), p('payload'), 168, 169, p('@location')]),
            ('split', [p('result'), p('payload'), -1, 0, p('@location')]),
            ('split', [p('payload'), p('payload'), 168, 1, p('@location')]),
            ('split', [p('result'), 0, 168, 1, p('@location')]),
            ('lane_copy', [p('payload'), 168, p('payload', 167), 168]),
            ('lane_copy', [p('payload'), 1025, p('payload', 512), 1]),
            ('lane_copy', [p('payload'), -1, p('payload', 512), 1]),
            ('mask', [p('payload', 1024), 255, 0]), ('mask', [0, 255, 0]),
            ('mask', [p('payload'), 256, 0]), ('mask', [p('payload'), 255, -1])):
        count += rejects(lambda: machine().primitive_body(role, args, 0))
    m = machine()
    m.primitive = 'split'
    count += rejects(lambda: m.primitive_body('split', [], 0))
    assert count == 12
    print('Primitive boundary model rejects twelve invalid/aliased/recursive borrowed inputs', flush=True)


def main(record, shard):
    boundaries()
    before = check.comparison.capture.sources()
    cases = list(check.composed.operation.cases(record))
    assert len(cases) == 8
    for case in cases if shard is None else [cases[shard]]:
        count = 0
        with patch.object(check.composed, 'scenarios', one_composed_case):
            assert check.inspect(case, False, True)[0] == 1
            for label, mutant in mutants(case):
                for inspect in (lambda c: check.direct(c, True), lambda c: check.inspect(c, False, True)):
                    try:
                        inspect(mutant)
                    except ValueError:
                        count += 1
                    else:
                        raise AssertionError('accepted primitive-body regression: ' + label)
            _, _, names, merged = check.closure(case, False)
            body = merged[names['split']]
            for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M),
                            re.sub(r'%mid\b', '%split_point', body)):
                assert body != control
                candidate = changed(case, body, control)
                assert check.direct(candidate, True) == 17 and check.inspect(candidate, False, True)[0] == 1
        assert count >= 40
        print(f'Primitive direct/composed bodies: {count} mutant executions rejected; four control executions PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all eight paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Compiler/runtime subprocesses forbidden; raw leaf and whole-call claims remain separately bounded')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
