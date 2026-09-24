#!/usr/bin/env python3
"""Mutate the actual SHA-3 completion adapter and its core cleanup dependencies."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_finish_adapter as check
import test_debug_output_finish as core_tests
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutants(case):
    root, _, selected = check.closure(case)
    _, _, core_selected = check.finish.closure(case.core)
    for label, core in core_tests.mutants(case.core):
        # The adapter intentionally maps all core errors to SecretMemory; the
        # core check already enforces the distinct underlying error identity.
        if label == 'wrong failure code':
            continue
        yield 'composed core: ' + label, replace(case, core=core)
    for name, body in selected.items():
        if name in core_selected:
            continue
        if 'ptr ' in body:
            yield 'by-value adapter/helper ABI', changed(case, body, body.replace('ptr ', 'ptr byval([24 x i8]) ', 1))
        if name == root:
            yield 'wrong result width', changed(case, body, body.replace('sret([24 x i8])', 'sret([16 x i8])', 1))
            yield 'direct payload read', changed(case, body, body.replace('bb3:',
                'bb3:\n  %descriptor = getelementptr i8, ptr %initialization, i64 8\n'
                '  %payload = load ptr, ptr %descriptor, align 8\n'
                '  %disclose = load i8, ptr %payload, align 1', 1))
        for label, lines in check.model.blocks(body).items():
            for index, line in enumerate(lines):
                alternatives = []
                if re.search(r'\bcall ', line):
                    alternatives.append('')
                    if 'llvm.memcpy' in line:
                        alternatives.append(re.sub(r'i64 24', 'i64 16', line))
                if match := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    alternatives.append(f'br i1 {match[1]}, label %{match[3]}, label %{match[2]}')
                if line == 'ret i8 4':
                    alternatives.append('ret i8 0')
                if re.fullmatch(r'store (i8|i64) [012], ptr %_0, align 8', line):
                    match = re.match(r'store (i8|i64) ([012]),', line)
                    alternatives.append(line.replace('store ' + match[1] + ' ' + match[2] + ',',
                                                     'store ' + match[1] + ' ' + str((int(match[2]) + 1) % 3) + ','))
                for alternative in alternatives:
                    assert alternative != line
                    new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line + ' -> ' + alternative, changed(case, body, replace_block(body, label, new))


def main(record):
    counts, controls = [], 0
    for case in check.begin.guard.final.cases(record):
        counts.append(rejects(check.inspect, case, mutants(case)))
        root, _, selected = check.closure(case)
        body = selected[root]
        for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M),
                        re.sub(r'%initialization1\b', '%completed_region', body)):
            assert control != body
            assert check.inspect(changed(case, body, control))[0] == 71
            controls += 1
        core_error = next(core for label, core in core_tests.mutants(case.core) if label == 'wrong failure code')
        assert core_error != case.core and check.inspect(replace(case, core=core_error))[0] == 71
        controls += 1
        print('Debug finish adapter mutation count: ' + str(counts[-1]), flush=True)
    assert len(counts) == 16 and all(count > 60 for count in counts) and controls == 48
    print(f'Debug finish adapters reject {sum(counts)} ownership/cleanup/mapping/ABI mutations; {controls} metadata/SSA/error-collapsing controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Retained artifacts only; subprocess execution forbidden; no production or release-gate changes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
