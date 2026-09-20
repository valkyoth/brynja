#!/usr/bin/env python3
"""Mutate retained ownership/cleanup/unwind artifacts without Rust execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_output_finish as check
from test_kmac_verify_comparisons import rejects


def mutants(core):
    root, names, selected = check.closure(core)
    body = selected[root]
    for label, old, new in (
        ('by-value owner', 'ptr align 8 %self)', 'ptr byval([24 x i8]) align 8 %self)'),
        ('wrong result width', 'sret([24 x i8])', 'sret([16 x i8])'),
        ('presence inverted', 'icmp eq i64 %12, 0', 'icmp ne i64 %12, 0'),
        ('incomplete accepted', 'icmp eq i64 %_7, %region.1', 'icmp ule i64 %_7, %region.1'),
        ('wrong progress field', 'ptr %self, i64 16', 'ptr %self, i64 8'),
        ('wrong handoff length', 'store i64 %region.12, ptr %35', 'store i64 0, ptr %35'),
        ('wrong handoff pointer', 'store ptr %region.01, ptr %34', 'store ptr %self, ptr %34'),
        ('error reported as success', 'store i8 1, ptr %_0', 'store i8 0, ptr %_0'),
        ('success reported as error', 'store i8 0, ptr %_0', 'store i8 1, ptr %_0'),
        ('wrong failure code', 'store i8 3,', 'store i8 2,'),
        ('wrong resumed exception pointer', 'ptr %38, 0', 'ptr null, 0'),
        ('wrong resumed exception selector', 'i32 %40, 1', 'i32 0, 1'),
        ('swallowed unwind', 'resume { ptr, i32 } %42', 'ret void'),
        ('direct owner-byte access', 'start:', 'start:\n  %secret = load ptr, ptr %self, align 8\n  %byte = load i8, ptr %secret, align 1'),
    ):
        yield label, core.replace(body, body.replace(old, new))
    for branch in (line for line in body.splitlines() if line.strip().startswith('br i1')):
        found = re.search(r'br i1 (\S+), label %(\S+), label %([^,\s]+)', branch)
        changed = branch.replace(found[0], f'br i1 {found[1]}, label %{found[3]}, label %{found[2]}')
        yield 'reversed finish branch', core.replace(body, body.replace(branch, changed))
    drop_lines = [line for line in body.splitlines() if re.search(r'\bcall void @', line)
                  and 'SecretRegionInitialization' in line]
    assert len(drop_lines) == 2
    for number, line in enumerate(drop_lines):
        # Replace one occurrence, since both normal calls are identical.
        index = body.find(line) if number == 0 else body.rfind(line)
        changed = body[:index] + body[index:].replace(line, '', 1)
        yield 'omitted normal destructor', core.replace(body, changed)
    invoked_drop = next(line for line in body.splitlines() if 'invoke void @' in line)
    edges = next(line for line in body.splitlines() if 'to label %bb14 unwind label %terminate' in line)
    yield 'omitted unwind destructor', core.replace(body, body.replace(invoked_drop + '\n' + edges, '  br label %bb14'))
    for edge in (line for line in body.splitlines() if 'to label' in line and 'unwind label %cleanup' in line):
        yield 'wrong unwind destination', core.replace(body, body.replace(edge, edge.replace('unwind label %cleanup', 'unwind label %bb12')))
    for name, function in selected.items():
        replacements = []
        if name == names['take']:
            replacements = [('store ptr null, ptr %self', 'store ptr %_0.0, ptr %self'),
                            ('ptr %self, i64 8', 'ptr %self, i64 16'),
                            ('ptr %_0.0, 0', 'ptr null, 0')]
        elif re.search(r'\bcall void @[^\n]+secret_memory_volatile23zeroize_region_volatile', function):
            wipe = next(line for line in function.splitlines() if 'call void @' in line
                        and 'secret_memory_volatile23zeroize_region_volatile' in line)
            replacements = [(wipe, ''), (wipe, wipe + '\n' + wipe),
                            ('i64 %region.1)', 'i64 0)'),
                            (wipe, wipe.replace('%region.0', '%self')),
                            ('icmp eq i64', 'icmp ne i64')]
        elif '5deref' in name or '9deref_mut' in name:
            replacements = [('ptr %self, i64 8', 'ptr %self, i64 16')]
        for old, new in replacements:
            yield 'actual helper ownership/cleanup regression', core.replace(function, function.replace(old, new))


def main(record):
    count = controls = 0
    for core, _, _, _ in check.writing.cases(record):
        count += rejects(check.inspect, core, mutants(core))
        root, _, selected = check.closure(core)
        body = selected[root]
        changed = re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M)
        assert changed != body
        assert check.inspect(core.replace(body, changed)) == 70
        controls += 1
    if (count, controls) != (256, 8):
        raise AssertionError(f'incomplete finish mutation campaign: {count}/{controls}')
    print(f'Debug finish rejects {count} LLVM ownership/cleanup/unwind mutations; {controls} debug-metadata controls PASS')
    print('Artifact-text and synthetic model faults only; subprocess execution forbidden; no release-gate change')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
