#!/usr/bin/env python3
"""Mutate actual debug reader forwarding and error/ownership helpers; no rebuild."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_kmac_bulk_bridge as check
from test_kmac_verify_comparisons import rejects


def changed(case, body, old, new):
    assert old in body and old != new
    field = 'kmac' if body in case.kmac else 'sha3'
    text = getattr(case, field)
    return replace(case, **{field: text.replace(body, body.replace(old, new, 1))})


def mutants(case):
    producer, selected = check.closure(case)
    for name, body in selected.items():
        if name == case.root or '14squeeze_secret' in name:
            yield 'by-value borrowed reader', changed(case, body, 'ptr align 8 %self', 'ptr byval([16 x i8]) align 8 %self')
            yield 'truncated output result ABI', changed(case, body, 'sret([24 x i8])', 'sret([16 x i8])')
            for line in body.splitlines():
                if re.search(r'^\s*call void @', line) and ('squeeze_secret' in line or 'Borrowed' in line):
                    match = re.search(check.comparison.SYMBOL, line)
                    args = check.comparison.arguments(line, match.end())
                    for index, value in ((1, 'ptr %output.0' if name == case.root else args[2]),
                                         (2, 'ptr %self'), (3, 'i64 0')):
                        yield 'wrong original reader/output/width', changed(case, body, line, line.replace(args[index], value, 1))
                    yield 'missing producer', changed(case, body, line, '')
                    yield 'duplicate producer', changed(case, body, line, line + '\n' + line)
                    yield 'unknown producer', changed(case, body, match[1], 'unreviewed_producer')
            yield 'payload read', changed(case, body, 'start:', 'start:\n  %leak = load i8, ptr ' +
                    ('%output.0' if name == case.root or case.accelerated else '%destination.0') + ', align 1')
            yield 'reader-state read', changed(case, body, 'start:', 'start:\n  %leak = load i8, ptr %self, align 1')
            if name != case.root:
                yield 'bulk turned final', changed(case, body, 'i1 zeroext false', 'i1 zeroext true')
                yield 'tail shape supplied on bulk path', changed(case, body, 'i8 undef', 'i8 7')
        if '7map_err' in name:
            for old, new in (('icmp eq i64 %0, 2', 'icmp ne i64 %0, 2'),
                             ('store i64 2, ptr %_0', 'store i64 1, ptr %_0'),
                             ('store i8 %_6,', 'store i8 0,'),
                             ('ptr %self, i64 8', 'ptr %self, i64 16')):
                yield 'result/error mapping', changed(case, body, old, new)
            for line in body.splitlines():
                if 'call void @llvm.memcpy.p0.p0.i64(' not in line:
                    continue
                for new in ('', line + '\n' + line, line.replace('i64 24', 'i64 16'),
                            line.replace('i1 false', 'i1 true')):
                    yield 'missing/duplicated/narrow/volatile descriptor handoff', changed(case, body, line, new)
                args = check.comparison.arguments(line, re.search(check.comparison.SYMBOL, line).end())
                yield 'wrong descriptor source', changed(case, body, line, line.replace(args[1], args[0], 1))
        if '4from' in name and 'call_once' not in name and '7map_err' not in name:
            if case.accelerated:
                yield 'backend error replaced', changed(case, body, 'ret i8 %error', 'ret i8 0')
            else:
                for line in body.splitlines():
                    if re.search(r'store i8 \d+, ptr %_0', line):
                        yield 'incorrect error variant', changed(case, body, line, re.sub(r'store i8 \d+', 'store i8 255', line))
        if 'call_once' in name:
            line = next(line for line in body.splitlines() if re.search(r'^\s*%\S+ = call i8 @', line))
            arg = check.comparison.arguments(line, re.search(check.comparison.SYMBOL, line).end())[0]
            yield 'error erased by adapter', changed(case, body, line, line.replace(arg, 'i8 0'))
    definition = check.comparison.definitions(case.sha3)[producer]
    yield 'producer definition absent', replace(case, sha3=case.sha3.replace(definition, ''))
    yield 'producer descriptor ABI changed', changed(case, definition, 'sret([24 x i8])', 'sret([16 x i8])')
    yield 'producer owns reader by value', changed(case, definition, 'ptr align 8 %self', 'ptr byval([16 x i8]) align 8 %self')


def main(record):
    count = controls = 0
    per_case = []
    for case in check.cases(record):
        value = rejects(check.inspect, case, mutants(case))
        assert value == (41 if case.accelerated else 44)
        count += value
        per_case.append(value)
        root = check.comparison.definitions(case.kmac)[case.root]
        clean = re.sub(r'^\s*#dbg_.*\n', '', root, flags=re.M)
        assert clean != root
        expected = check.inspect(case)
        assert check.inspect(replace(case, kmac=case.kmac.replace(root, clean))) == expected
        renamed = re.sub(r'%_3\b', '%bulk_result', root)
        assert renamed != root
        assert check.inspect(replace(case, kmac=case.kmac.replace(root, renamed))) == expected
        controls += 2
    assert len(per_case) == 24 and controls == 48 and count == 1032
    print(f'Debug KMAC bulk bridges reject {count} LLVM forwarding/ownership/error/ABI mutations; {controls} metadata/SSA controls PASS')
    print('Per-path mutation counts: ' + repr(per_case))
    print('Producer payload behavior is opaque; artifact-only checks, subprocess execution forbidden')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
