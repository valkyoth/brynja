#!/usr/bin/env python3
"""Retained debug clearing mutations; no compiler or runtime subprocesses."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_volatile_clear as check
from test_kmac_verify_comparisons import rejects


def mutants(core):
    root, precondition, selected = check.closure(core)
    body = selected[root]
    for old, new in (
        ('i8 0, ptr align', 'i8 1, ptr align'),
        ('(i8 4)', '(i8 1)'),
        ('icmp eq i64', 'icmp ne i64'),
        ('start:', 'start:\n  %secret = load i8, ptr %region.0, align 1'),
        ('start:', 'start:\n  store i8 0, ptr %region.0, align 1'),
    ):
        yield 'root zero/fence/presence/payload regression', core.replace(body, body.replace(old, new))
    for line in body.splitlines():
        if line.lstrip().startswith(';'):
            continue
        if 'call ' in line and ('write_volatile' in line or 'compiler_fence' in line):
            yield 'omitted root operation', core.replace(body, body.replace(line, ''))
        if line.strip().startswith('br i1'):
            edges = re.search(r'br i1 (\S+), label %(\S+), label %([^,\s]+)', line)
            new = line.replace(edges[0], f'br i1 {edges[1]}, label %{edges[3]}, label %{edges[2]}')
            yield 'wrong loop branch', core.replace(body, body.replace(line, new))
    for name, function in selected.items():
        replacements = []
        if '9into_iter' in name:
            end = next(line for line in function.splitlines() if 'getelementptr inbounds nuw i8' in line)
            replacements = [(end, end.replace('i64 %self.1', 'i64 0')),
                            ('poison, ptr %self.0, 0', 'poison, ptr null, 0')]
        elif '4next' in name:
            step = next(line for line in function.splitlines() if 'getelementptr inbounds nuw i8' in line)
            fields = re.search(r'(%\S+) = getelementptr inbounds nuw i8, ptr (%\S+), i64 1', step)
            assert fields is not None
            advanced, original = fields.groups()
            output = next(line for line in function.splitlines() if re.search(r'store ptr %\S+, ptr %_0,', line))
            replacements = [('icmp eq ptr', 'icmp ne ptr'),
                            (step, step.replace('i64 1', 'i64 0')),
                            ('store ptr ' + advanced + ', ptr %self', 'store ptr ' + original + ', ptr %self'),
                            (output, re.sub(r'store ptr %\S+,', 'store ptr ' + advanced + ',', output))]
        elif '14write_volatile' in name and name != precondition:
            store = next(line for line in function.splitlines() if 'store volatile i8' in line)
            call = next(line for line in function.splitlines() if 'call void' in line and 'precondition_check' in line)
            replacements = [(store, ''), (store, store.replace('volatile ', '')),
                            (store, store.replace('i8 %src', 'i8 1')),
                            (store, store + '\n' + store),
                            (call, ''), (call, call.replace('i64 1,', 'i64 2,'))]
        elif '14compiler_fence' in name:
            fence = next(line for line in function.splitlines() if 'fence ' in line and 'seq_cst' in line)
            replacements = [(fence, ''), (fence, fence + '\n' + fence),
                            ('singlethread") seq_cst', 'singlethread") release'),
                            ('i64 4, label %bb3', 'i64 4, label %bb5')]
        for old, new in replacements:
            yield 'bound helper regression: ' + old, core.replace(function, function.replace(old, new))


def memory_controls():
    reference = check.model.Model({}, '', '')
    indexed = check.ClearModel({}, '', '', 0)
    for machine in (reference, indexed):
        machine.allocate('local', 24)
        machine.allocate('second', 24)
    for index in range(100):
        region = 'local' if index % 3 else 'second'
        width = (1, 4, 8)[index % 3]
        pointer = check.model.Pointer(region, index % (25 - width))
        reference.store(pointer, width, index)
        indexed.store(pointer, width, index)
        assert indexed.memory == reference.memory


def main(record):
    memory_controls()
    count = controls = 0
    for core, _, _, _ in check.writing.cases(record):
        count += rejects(check.inspect, core, mutants(core))
        root, _, selected = check.closure(core)
        body = selected[root]
        changed = re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M)
        assert changed != body
        assert check.inspect(core.replace(body, changed)) == len(check.lengths())
        controls += 1
    if (count, controls) != (192, 8):
        raise AssertionError(f'incomplete debug clearing campaign: {count}/{controls}')
    print(f'Debug volatile clearing rejects {count} retained-LLVM regressions; {controls} metadata controls PASS')
    print('Indexed descriptor memory matches 100 overlapping-store cases; subprocess execution forbidden')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
