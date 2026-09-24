#!/usr/bin/env python3
"""Retained debug constructor/helper mutations; compiler/runtime execution forbidden."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_fips202_output as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def changed(case, body, replacement):
    assert body != replacement
    return replace(case, **{field: getattr(case, field).replace(body, replacement)
                           for field in ('sha3', 'hash_core') if body in getattr(case, field)})


def mutants(case):
    root, selected = check.closure(case)
    functions = {name: (check.model.parameters(body), check.model.blocks(body)) for name, body in selected.items()}
    covered = check.covered_blocks(functions)
    for name, body in selected.items():
        if name == root:
            for old, new in (('sret([32 x i8])', 'sret([24 x i8])'),
                             ('ptr align 1 %bytes.0', 'ptr byval([8 x i8]) align 1 %bytes.0') if 'ptr align 1 %bytes.0' in body
                             else ('ptr %bytes.0', 'ptr byval([8 x i8]) %bytes.0'),
                             ('start:', 'start:\n  %leak = load i8, ptr %bytes.0, align 1')):
                yield 'constructor ABI/payload regression', changed(case, body, body.replace(old, new, 1))
        for label, lines in functions[name][1].items():
            if (name, label) not in covered:
                continue
            for index, line in enumerate(lines):
                replacements = []
                if match := re.search(r'icmp (eq|ne|ult|ule) i', line):
                    replacements.append(line.replace(match[0], 'icmp ' + {'eq':'ne', 'ne':'eq', 'ult':'uge', 'ule':'ugt'}[match[1]] + ' i'))
                if match := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    replacements.append(f'br i1 {match[1]}, label %{match[3]}, label %{match[2]}')
                if 'call void @llvm.memcpy.' in line:
                    replacements.extend(['', line.replace('i64 32', 'i64 16')])
                if name == root and label == 'bb8' and line.startswith('store ') and '.dbg.spill' not in line:
                    replacements.append(re.sub(r'^(store (?:ptr|i\d+)) %\S+,', r'\1 0,', line).replace('store ptr 0,', 'store ptr null,'))
                if 'exact_bit_len' in name and ('i64 8)' in line or 'i64 1)' in line):
                    replacements.append(line.replace('i64 8)', 'i64 7)').replace('i64 1)', 'i64 0)'))
                if 'insertvalue { i64, ptr } { i64 0, ptr poison }' in line:
                    replacements.extend([line.replace('{ i64 0, ptr poison }', '{ i64 1, ptr poison }'),
                                         line.replace('{ i64 0, ptr poison }', '{ i64 2, ptr poison }')])
                if '9start_bound' in name or '9end_bound' in name:
                    if re.fullmatch(r'%\S+ = getelementptr inbounds(?: nuw)? i8, ptr %self, i64 [12]', line):
                        replacements.append(line[:-1] + ('2' if line.endswith('1') else '1'))
                for replacement in replacements:
                    assert replacement != line
                    new = lines[:index] + ([replacement] if replacement else []) + lines[index + 1:]
                    yield f'shape/length/descriptor/helper regression: {name}/{label}/{line}', changed(case, body, replace_block(body, label, new))
    for field in ('sha3', 'hash_core'):
        text = getattr(case, field)
        marker = r'c"\00\01\08"'
        if marker in text:
            for replacement in (r'c"\00\00\08"', r'c"\00\01\09"', r'c"\01\01\08"'):
                # Identical constant definitions in the two artifact modules
                # are changed together, avoiding an artificial name collision.
                yield 'range constant changed', replace(case, sha3=case.sha3.replace(marker, replacement),
                                                       hash_core=case.hash_core.replace(marker, replacement))
            break
    helper = next(body for name, body in selected.items() if 'RangeBounds' in name and '8contains' in name)
    yield 'missing actual range helper', replace(case, hash_core=case.hash_core.replace(helper, ''))


def model_controls():
    machine = check.model.Model({}, '', '')
    for value in (0, 1, 255, -1, check.model.MASK):
        for pointer in ('null', 'poison', 'undef'):
            result = machine.value('{ i64 ' + str(value) + ', ptr ' + pointer + ' }', {})
            assert result == (value & check.model.MASK, 0 if pointer == 'null' else check.model.UNKNOWN)
    for value in ('{ ptr 1, i64 0 }', '{ i64 null, ptr poison }', '{ i64 0, ptr poison, i8 1 }'):
        try:
            machine.value(value, {})
        except ValueError:
            continue
        raise AssertionError('malformed literal aggregate accepted')


def main(record):
    model_controls()
    count = controls = 0
    per_case = []
    for case in check.cases(record):
        count += (value := rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        assert value == 44
        per_case.append(value)
        root, selected = check.closure(case)
        body = selected[root]
        for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M), re.sub(r'%_16\b', '%built_output', body)):
            assert control != body
            assert check.inspect(changed(case, body, control), False) == (60, 19)
            controls += 1
    pin_checks = 0
    for config in check.HASH_CORE:
        target = config.split('-debug-', 1)[0].split('-', 1)[1]
        relative = Path(config) / target / 'debug/deps/brynja_hash_sha3-original.ll'
        with patch.object(Path, 'read_bytes', return_value=b'changed helper bytes'):
            try:
                check.supplemental(record, relative)
            except ValueError:
                pin_checks += 1
            else:
                raise AssertionError('changed supplemental bytes accepted')
    assert len(per_case) == 8 and controls == 16 and pin_checks == 8 and count == 352
    print(f'Debug output constructor rejects {count} LLVM/constant/dependency mutations and {pin_checks} supplemental pin regressions; {controls} metadata/SSA controls PASS')
    print('Per-configuration mutation counts: ' + repr(per_case))
    print('Literal aggregates: 15 value controls and three malformed constants rejected; no compiler/runtime rerun')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
