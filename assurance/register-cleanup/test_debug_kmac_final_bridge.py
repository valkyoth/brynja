#!/usr/bin/env python3
"""Mutate retained final-reader handoff, destructor and unwind dependencies."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_kmac_final_bridge as check
from test_kmac_verify_comparisons import rejects


def changed(case, body, old, new):
    assert old in body and old != new
    fields = {field: getattr(case, field).replace(body, body.replace(old, new, 1))
              for field in ('kmac', 'sha3', 'core') if body in getattr(case, field)}
    assert fields
    return replace(case, **fields)


def mutants(case):
    producer, wipe, selected = check.closure(case)
    for name, body in selected.items():
        if name == case.root or '25squeeze_final_bits_secret' in name:
            yield 'short output-result ABI', changed(case, body, 'sret([24 x i8])', 'sret([16 x i8])')
            yield 'by-value owner', changed(case, body, 'ptr align ', 'ptr byval([8 x i8]) align ')
            valid = '%valid' if name == case.root else '%valid_bits'
            yield 'wrong final-bit ABI', changed(case, body, 'i8 ' + valid + ')', 'i16 ' + valid + ')')
            for pointer in ('%output.0', '%self' if name == case.root else '%0'):
                yield 'unowned payload or state read', changed(case, body, 'start:',
                      'start:\n  %disclose = load i8, ptr ' + pointer + ', align 1')
        for line in body.splitlines():
            call = re.search(check.comparison.SYMBOL, line)
            if call is not None and re.search(r'^\s*(?:%\S+ = )?call ', line) and 'panic_in_cleanup' not in line:
                # Every real call here either carries ownership or requests
                # cleanup. Drop both the call and its result assignment.
                yield 'missing helper/cleanup', changed(case, body, line, '')
                if not any(token in call[1] for token in ('call_once', '4from', '8is_empty')):
                    yield 'duplicate helper/cleanup', changed(case, body, line, line + '\n' + line)
                if 'llvm.memcpy' in call[1]:
                    yield 'partial descriptor move', changed(case, body, line, line.replace('i64 24', 'i64 16'))
                if call[1] == wipe:
                    args = check.comparison.arguments(line, call.end())
                    yield 'wrong volatile extent', changed(case, body, line, line.replace(args[1], 'i64 1'))
                    yield 'null clear pointer', changed(case, body, line, line.replace(args[0], 'ptr null'))
                if '25squeeze_final_bits_secret' in call[1]:
                    args = check.comparison.arguments(line, call.end())
                    for index, new in ((1, 'ptr %self'), (2, 'ptr %self'), (3, 'i64 0'), (4, 'i8 0')):
                        yield 'altered consuming arguments', changed(case, body, line, line.replace(args[index], new))
            if re.search(r'^\s*invoke void @', line):
                lines = body.splitlines()
                index = lines.index(line)
                edge = lines[index + 1]
                match = re.search(r'to label %(\S+) unwind label %([^,\s]+)', edge)
                assert match is not None
                yield 'skipped producer or unwind destructor', changed(case, body, line + '\n' + edge, '  br label %' + match[1])
                if producer in line:
                    yield 'producer unwind bypasses cleanup', changed(case, body, edge,
                          edge.replace('unwind label %' + match[2], 'unwind label %' + match[1]))
                    for old, new in (('i1 zeroext true', 'i1 zeroext false'),
                                     ('i8 %valid_bits', 'i8 0'), ('i64 %output.1', 'i64 0'),
                                     ('ptr align 8 %self', 'ptr %output.0')):
                        yield 'wrong producer final shape or owner', changed(case, body, line, line.replace(old, new))
            if re.search(r'getelementptr inbounds(?: nuw)? i8, ptr %self, i64 \d+', line) and 'map_err' not in name:
                match = re.search(r'i64 (\d+)', line)
                yield 'wrong cleanup offset', changed(case, body, line, line.replace(match[0], 'i64 ' + str(int(match[1]) + 1)))
            if re.search(r'^\s*store i8 1, ptr %\d+', line):
                yield 'terminal state not set', changed(case, body, line, line.replace('store i8 1', 'store i8 0'))
            if re.search(r'^\s*store i64 0, ptr %\d+', line):
                yield 'cursor not reset', changed(case, body, line, line.replace('store i64 0', 'store i64 1'))
            if line.strip().startswith('resume { ptr, i32 }'):
                yield 'swallowed producer exception', changed(case, body, line, '  ret void')
            if re.search(r'insertvalue \{ ptr, i32 } .*?, ptr %\S+, 0', line):
                yield 'substituted exception identity', changed(case, body, line, re.sub(r', ptr %\S+, 0', ', ptr null, 0', line))
            if re.search(r'insertvalue \{ ptr, i32 } .*?, i32 %\S+, 1', line):
                yield 'substituted exception selector', changed(case, body, line, re.sub(r', i32 %\S+, 1', ', i32 0, 1', line))
        if '7map_err' in name:
            for old, new in (('icmp eq i64 %0, 2', 'icmp ne i64 %0, 2'),
                             ('store i64 2, ptr %_0', 'store i64 1, ptr %_0'),
                             ('store i8 %_6,', 'store i8 0,')):
                yield 'error/result confusion', changed(case, body, old, new)
        if '4from' in name and 'call_once' not in name and '7map_err' not in name:
            yield 'backend error erased', changed(case, body, 'ret i8 %error', 'ret i8 0')
        if '8is_empty' in name:
            yield 'nonempty clear skipped', changed(case, body, 'icmp eq i64', 'icmp ne i64')
    for text, symbol in ((case.sha3, producer), (case.core, wipe)):
        definition = check.comparison.definitions(text)[symbol]
        field = 'sha3' if symbol == producer else 'core'
        yield 'actual boundary definition removed', replace(case, **{field: text.replace(definition, '')})
        pointer = 'ptr align 8 %self' if symbol == producer else 'ptr align 1 %region.0'
        # Rust 1.98 omits explicit align 1 on byte pointers.
        if pointer not in definition:
            pointer = 'ptr %region.0'
        yield 'opaque boundary changed to by-value', changed(case, definition, pointer,
                pointer.replace('ptr ', 'ptr byval([8 x i8]) ', 1))


def main(record):
    count = controls = 0
    per_case = []
    for case in check.cases(record):
        value = rejects(lambda value: check.inspect(value, False), case, mutants(case))
        assert value == (86 if case.compiler == '1.90.0' else 85)
        per_case.append(value)
        count += value
        root = check.comparison.definitions(case.kmac)[case.root]
        stripped = re.sub(r'^\s*#dbg_.*\n', '', root, flags=re.M)
        renamed = re.sub(r'%_4\b', '%final_result', root)
        for control in (stripped, renamed):
            assert control != root
            assert check.inspect(replace(case, kmac=case.kmac.replace(root, control)), False) == 84
            controls += 1
    assert len(per_case) == 8 and controls == 16 and count == 684
    print(f'Debug accelerated final bridges reject {count} LLVM handoff/drop/clear/unwind mutations; {controls} metadata/SSA controls PASS')
    print('Per-path mutation counts: ' + repr(per_case))
    print('Opaque producer/volatile boundaries; retained artifact tests only, subprocess execution forbidden')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
